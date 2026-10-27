// SPDX-License-Identifier: GPL-2.0
//
// Kernel side of the agent's eBPF collectors. Three ring buffers carry events
// to user space:
//   shell_events: commands run by bash, from uprobes on the bash binary
//   file_events: file create, write-open, delete, rename and chmod with the
//                acting process, from the LSM path hooks (CONFIG_SECURITY_PATH)
//   net_events:  every TCP connect and accept with the acting process, so
//                short connections are not missed between /proc polls
//
// Paths are sent as name slots from the leaf up to the root; user space
// reverses them. Event layouts must match ../events.go.

#include "headers/kernel.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"
#include "headers/bpf_core_read.h"

char __license[] SEC("license") = "GPL";

#define FMODE_WRITE 0x2
#define AF_INET 2
#define AF_INET6 10

// A path is a fixed array of name slots: slot 0 holds the leaf name (empty
// when there is none) and the following slots its parents up to the root.
// Fixed slots keep every offset constant, which keeps the verifier's work
// small enough for two walks in one program.
#define NAME_SLOT 128
#define PATH_SLOTS 32
#define PATH_BUF (NAME_SLOT * PATH_SLOTS)
#define PATH_TRUNCATED 0x80000000

enum file_op {
	FILE_CREATE = 1,
	FILE_WRITE = 2,
	FILE_DELETE = 3,
	FILE_RENAME = 4,
	FILE_CHMOD = 5,
};

enum net_op {
	NET_CONNECT = 1,
	NET_ACCEPT = 2,
};

struct file_event {
	u32 pid;
	u32 ppid;
	u32 uid;
	u32 op;
	u32 mode;
	u32 path_len;
	u32 path2_len;
	u32 _pad;
	char comm[16];
	char path[PATH_BUF];  // the file, or the new name for a rename
	char path2[PATH_BUF]; // the old name for a rename
};

struct net_event {
	u32 pid;
	u32 ppid;
	u32 uid;
	u16 op;
	u16 family;
	u16 lport; // host byte order
	u16 rport; // network byte order
	u32 _pad;
	u8 laddr[16];
	u8 raddr[16];
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 << 20);
} file_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} net_events SEC(".maps");

// Set by the loader so the agent's own activity is not reported.
volatile const u32 agent_tgid = 0;

static __always_inline bool skip_self(void)
{
	return (bpf_get_current_pid_tgid() >> 32) == agent_tgid;
}

static __always_inline void fill_task(u32 *pid, u32 *ppid, u32 *uid, char *comm)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	*pid = bpf_get_current_pid_tgid() >> 32;
	*ppid = BPF_CORE_READ(task, real_parent, tgid);
	*uid = (u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(comm, 16);
}

static __always_inline struct mount *real_mount(struct vfsmount *mnt)
{
	return (struct mount *)((void *)mnt -
				__builtin_preserve_field_info(((struct mount *)0)->mnt, BPF_FIELD_BYTE_OFFSET));
}

static __always_inline void read_name(char *slot, struct dentry *d)
{
	const unsigned char *name = BPF_CORE_READ(d, d_name.name);
	if (bpf_probe_read_kernel_str(slot, NAME_SLOT, name) < 0)
		slot[0] = 0;
}

// build_path fills the name slots of buf with leaf (when set) and every
// component of dentry up to the root of the mount namespace, crossing mount
// points. It returns the number of slots used, with PATH_TRUNCATED set when
// the root was not reached.
static __always_inline u32 build_path(char *buf, struct dentry *leaf, struct dentry *dentry,
				      struct vfsmount *vfsmnt)
{
	buf[0] = 0;
	if (leaf)
		read_name(buf, leaf);
	struct mount *mnt = real_mount(vfsmnt);
	struct dentry *mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

	for (u32 i = 1; i < PATH_SLOTS; i++) {
		char *slot = &buf[i * NAME_SLOT];
		slot[0] = 0;
		if (dentry == mnt_root) {
			// Mount crossings use up an empty slot.
			struct mount *parent_mnt = BPF_CORE_READ(mnt, mnt_parent);
			if (parent_mnt == mnt)
				return i;
			dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
			mnt = parent_mnt;
			mnt_root = BPF_CORE_READ(mnt, mnt.mnt_root);
			continue;
		}
		struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
		if (parent == dentry)
			return i;
		read_name(slot, dentry);
		dentry = parent;
	}
	return PATH_SLOTS | PATH_TRUNCATED;
}

static __always_inline int emit_file(u32 op, u32 mode, struct dentry *leaf, const struct path *dir,
				     struct dentry *leaf2, const struct path *dir2)
{
	if (skip_self())
		return 0;
	struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_task(&e->pid, &e->ppid, &e->uid, e->comm);
	e->op = op;
	e->mode = mode;
	e->_pad = 0;
	e->path_len = build_path(e->path, leaf, BPF_CORE_READ(dir, dentry), BPF_CORE_READ(dir, mnt));
	e->path2_len = 0;
	if (dir2)
		e->path2_len = build_path(e->path2, leaf2, BPF_CORE_READ(dir2, dentry), BPF_CORE_READ(dir2, mnt));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// security_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev)
// runs for open(O_CREAT) of a new file as well as mknod.
SEC("kprobe/security_path_mknod")
int file_create(struct pt_regs *ctx)
{
	return emit_file(FILE_CREATE, (u32)PT_REGS_PARM3(ctx), (struct dentry *)PT_REGS_PARM2(ctx),
			 (const struct path *)PT_REGS_PARM1(ctx), 0, 0);
}

// security_file_open(struct file *file)
SEC("kprobe/security_file_open")
int file_open(struct pt_regs *ctx)
{
	struct file *f = (struct file *)PT_REGS_PARM1(ctx);
	if (!(BPF_CORE_READ(f, f_mode) & FMODE_WRITE))
		return 0;
	struct path p;
	if (bpf_core_read(&p, sizeof(p), &f->f_path))
		return 0;
	// The file's own dentry is the start of the walk, so there is no leaf.
	return emit_file(FILE_WRITE, 0, 0, &p, 0, 0);
}

// security_path_unlink(const struct path *dir, struct dentry *dentry)
SEC("kprobe/security_path_unlink")
int file_delete(struct pt_regs *ctx)
{
	return emit_file(FILE_DELETE, 0, (struct dentry *)PT_REGS_PARM2(ctx),
			 (const struct path *)PT_REGS_PARM1(ctx), 0, 0);
}

// security_path_rename(const struct path *old_dir, struct dentry *old_dentry,
//                      const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
SEC("kprobe/security_path_rename")
int file_rename(struct pt_regs *ctx)
{
	return emit_file(FILE_RENAME, 0, (struct dentry *)PT_REGS_PARM4(ctx),
			 (const struct path *)PT_REGS_PARM3(ctx), (struct dentry *)PT_REGS_PARM2(ctx),
			 (const struct path *)PT_REGS_PARM1(ctx));
}

// security_path_chmod(const struct path *path, umode_t mode)
SEC("kprobe/security_path_chmod")
int file_chmod(struct pt_regs *ctx)
{
	return emit_file(FILE_CHMOD, (u32)PT_REGS_PARM2(ctx), 0, (const struct path *)PT_REGS_PARM1(ctx), 0, 0);
}

static __always_inline int emit_net(u16 op, struct sock *sk)
{
	if (!sk || skip_self())
		return 0;
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_task(&e->pid, &e->ppid, &e->uid, e->comm);
	e->op = op;
	e->family = family;
	e->_pad = 0;
	e->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->rport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	__builtin_memset(e->laddr, 0, sizeof(e->laddr));
	__builtin_memset(e->raddr, 0, sizeof(e->raddr));
	if (family == AF_INET) {
		bpf_core_read(e->laddr, 4, &sk->__sk_common.skc_rcv_saddr);
		bpf_core_read(e->raddr, 4, &sk->__sk_common.skc_daddr);
	} else {
		bpf_core_read(e->laddr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
		bpf_core_read(e->raddr, 16, &sk->__sk_common.skc_v6_daddr);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// tcp_connect(struct sock *sk) runs in the connecting process after the
// local port is bound and before the SYN is sent.
SEC("kprobe/tcp_connect")
int net_connect(struct pt_regs *ctx)
{
	return emit_net(NET_CONNECT, (struct sock *)PT_REGS_PARM1(ctx));
}

// inet_csk_accept returns the new connection's sock in the accepting process.
SEC("kretprobe/inet_csk_accept")
int net_accept(struct pt_regs *ctx)
{
	return emit_net(NET_ACCEPT, (struct sock *)PT_REGS_RC(ctx));
}

// Shell commands: bash's readline() returns each line typed at an
// interactive prompt; parse_and_execute() runs strings (bash -c, eval,
// traps). Both are exported by bash, so uprobes find them by name.
#define CMD_LEN 512

enum shell_src {
	SHELL_INTERACTIVE = 1,
	SHELL_STRING = 2,
};

struct shell_event {
	u32 pid;
	u32 ppid;
	u32 uid;
	u32 src;
	char comm[16];
	char cmd[CMD_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} shell_events SEC(".maps");

static __always_inline int emit_shell(u32 src, const char *cmd)
{
	if (!cmd || skip_self())
		return 0;
	struct shell_event *e = bpf_ringbuf_reserve(&shell_events, sizeof(*e), 0);
	if (!e)
		return 0;
	if (bpf_probe_read_user_str(e->cmd, CMD_LEN, cmd) <= 1) {
		// NULL at end of input, or an empty line.
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	fill_task(&e->pid, &e->ppid, &e->uid, e->comm);
	e->src = src;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("uretprobe/readline")
int shell_readline(struct pt_regs *ctx)
{
	return emit_shell(SHELL_INTERACTIVE, (const char *)PT_REGS_RC(ctx));
}

// parse_and_execute(char *string, const char *from_file, int flags)
SEC("uprobe/parse_and_execute")
int shell_string(struct pt_regs *ctx)
{
	return emit_shell(SHELL_STRING, (const char *)PT_REGS_PARM1(ctx));
}
