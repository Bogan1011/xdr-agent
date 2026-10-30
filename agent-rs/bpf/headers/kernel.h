/* Minimal kernel types for the agent's BPF programs.
 *
 * Every struct is marked preserve_access_index, so only the names of the
 * structs and fields matter: offsets are relocated against the running
 * kernel's BTF at load time (CO-RE). Declare only the fields that are read.
 */
#pragma once

#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef __u16 umode_t;
typedef _Bool bool;

enum bpf_map_type {
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long r15, r14, r13, r12, bp, bx, r11, r10, r9, r8;
	unsigned long ax, cx, dx, si, di, orig_ax, ip, cs, flags, sp, ss;
};
#elif defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#endif

struct qstr {
	const unsigned char *name;
};

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
};

struct vfsmount {
	struct dentry *mnt_root;
};

struct mount {
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
};

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct file {
	struct path f_path;
	unsigned int f_mode;
};

struct task_struct {
	int tgid;
	struct task_struct *real_parent;
};

struct in6_addr {
	__u8 s6_addr[16];
};

struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	unsigned short skc_num;
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
};

struct sock {
	struct sock_common __sk_common;
};

struct msghdr {
	void *msg_name;
	int msg_namelen;
};

struct in_addr {
	__be32 s_addr;
};

struct sockaddr_in {
	unsigned short sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
};

struct sockaddr_in6 {
	unsigned short sin6_family;
	__be16 sin6_port;
	struct in6_addr sin6_addr;
};

#pragma clang attribute pop
