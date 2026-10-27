import { useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

// Terminal shows a remote shell streamed over a WebSocket. Read-only
// terminals watch a shell someone else is using.
export default function Terminal({ url, readOnly = false, onEnd }: { url: string; readOnly?: boolean; onEnd?: (msg: string) => void }) {
  const box = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<"connecting" | "open" | "ended">("connecting");
  const [reason, setReason] = useState("");
  const endRef = useRef(onEnd);
  endRef.current = onEnd;

  useEffect(() => {
    const term = new XTerm({
      cursorBlink: !readOnly,
      disableStdin: readOnly,
      fontFamily: 'ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace',
      fontSize: 13,
      scrollback: 5000,
      theme: { background: "#05070d", foreground: "#d7e2f0", cursor: "#38e1ff" },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(box.current!);
    fit.fit();

    const sep = url.includes("?") ? "&" : "?";
    const ws = new WebSocket(readOnly ? url : `${url}${sep}cols=${term.cols}&rows=${term.rows}`);
    ws.binaryType = "arraybuffer";
    let ended = false;
    const finish = (msg: string) => {
      if (ended) return;
      ended = true;
      setState("ended");
      setReason(msg);
      term.write(`\r\n\x1b[2m[${msg}]\x1b[0m\r\n`);
      endRef.current?.(msg);
    };
    ws.onopen = () => {
      setState("open");
      if (!readOnly) term.focus();
    };
    ws.onmessage = (e) => {
      if (typeof e.data === "string") {
        try {
          const m = JSON.parse(e.data);
          if (m.t === "exit") finish(m.msg || "session ended");
        } catch {
          /* ignore */
        }
        return;
      }
      term.write(new Uint8Array(e.data as ArrayBuffer));
    };
    ws.onclose = () => finish("disconnected");
    const send = (m: object) => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify(m));
    const input = readOnly ? undefined : term.onData((d) => send({ t: "i", d }));
    const resize = term.onResize(({ cols, rows }) => send({ t: "r", c: cols, r: rows }));
    const ro = new ResizeObserver(() => fit.fit());
    ro.observe(box.current!);

    return () => {
      ro.disconnect();
      input?.dispose();
      resize.dispose();
      ws.onclose = null;
      ws.close();
      term.dispose();
    };
  }, [url, readOnly]);

  return (
    <div className="terminal-wrap">
      <div className="terminal-status small">
        {state === "connecting" && <span className="muted">Connecting…</span>}
        {state === "open" && (
          <span className="status status-good">
            <span>●</span> {readOnly ? "Watching live (read-only)" : "Connected"}
          </span>
        )}
        {state === "ended" && <span className="muted">Ended: {reason}</span>}
      </div>
      <div className="terminal" ref={box} />
    </div>
  );
}
