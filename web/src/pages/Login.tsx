import { FormEvent, useEffect, useRef, useState } from "react";
import { ApiError, api } from "../api";
import { Logo } from "../components/Logo";

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.login(username, password, code);
      onLogin();
    } catch (err) {
      if (err instanceof ApiError && err.data.mfa_required) setNeedCode(true);
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <div className="login-bg" aria-hidden>
        <span className="aurora a1" />
        <span className="aurora a2" />
        <span className="aurora a3" />
        <div className="login-floor"><div /></div>
        <NetworkCanvas />
      </div>

      <section className="login-hero">
        <div className="login-logo"><Logo size={88} animated /></div>
        <h1 className="login-title">Ironsight<b>XDR</b></h1>
        <p className="login-tag">See every threat across your fleet. Stop it before it spreads.</p>
        <ul className="login-points">
          <li><span /> Real-time endpoint detection and response</li>
          <li><span /> Prevention policies and threat intel</li>
          <li><span /> Privileged access with recorded sessions</li>
        </ul>
      </section>

      <form className="login-card" onSubmit={submit}>
        <div className="login-card-head">
          <Logo size={34} />
          <div>
            <div className="login-card-title">Welcome back</div>
            <div className="muted small">Sign in to the Ironsight console</div>
          </div>
        </div>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            autoFocus
          />
        </label>
        {needCode && (
          <label>
            Authenticator code
            <input
              className="mono"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoFocus
            />
          </label>
        )}
        {error && <div className="error">{error}</div>}
        <button className="primary login-submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <div className="login-foot muted small">
          <span className="pulse" aria-hidden /> Protected by mTLS and audit logging
        </div>
      </form>
    </div>
  );
}

type Dot = { x: number; y: number; vx: number; vy: number; r: number; hue: number };

// NetworkCanvas draws drifting nodes that link up when close, like hosts
// talking on a network; nodes lean towards the pointer. It pauses when the
// tab is hidden and draws one still frame when reduced motion is asked for.
function NetworkCanvas() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current!;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const pointer = { x: -9999, y: -9999 };
    let w = 0;
    let h = 0;
    let dots: Dot[] = [];
    let raf = 0;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.clientWidth;
      h = canvas.clientHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const n = Math.round(Math.min(90, Math.max(36, (w * h) / 16000)));
      dots = Array.from({ length: n }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.35,
        vy: (Math.random() - 0.5) * 0.35,
        r: 1 + Math.random() * 1.8,
        hue: Math.random(),
      }));
    };

    const color = (t: number, a: number) =>
      t < 0.5 ? `rgba(255, 122, 168, ${a})` : t < 0.8 ? `rgba(255, 179, 122, ${a})` : `rgba(182, 156, 255, ${a})`;

    const frame = () => {
      ctx.clearRect(0, 0, w, h);
      const link = 130;
      for (const d of dots) {
        const dx = pointer.x - d.x;
        const dy = pointer.y - d.y;
        const dist = Math.hypot(dx, dy);
        if (dist < 180 && dist > 1) {
          d.vx += (dx / dist) * 0.012;
          d.vy += (dy / dist) * 0.012;
        }
        d.vx = Math.max(-0.6, Math.min(0.6, d.vx * 0.995));
        d.vy = Math.max(-0.6, Math.min(0.6, d.vy * 0.995));
        d.x += d.vx;
        d.y += d.vy;
        if (d.x < 0 || d.x > w) d.vx *= -1;
        if (d.y < 0 || d.y > h) d.vy *= -1;
      }
      ctx.lineWidth = 1;
      for (let i = 0; i < dots.length; i++) {
        for (let j = i + 1; j < dots.length; j++) {
          const a = dots[i];
          const b = dots[j];
          const dist = Math.hypot(a.x - b.x, a.y - b.y);
          if (dist < link) {
            ctx.strokeStyle = color(a.hue, (1 - dist / link) * 0.32);
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }
      for (const d of dots) {
        ctx.fillStyle = color(d.hue, 0.9);
        ctx.beginPath();
        ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
        ctx.fill();
      }
      if (!still && document.visibilityState === "visible") raf = requestAnimationFrame(frame);
    };

    const onMove = (e: PointerEvent) => {
      const r = canvas.getBoundingClientRect();
      pointer.x = e.clientX - r.left;
      pointer.y = e.clientY - r.top;
    };
    const onVisible = () => {
      cancelAnimationFrame(raf);
      if (document.visibilityState === "visible") raf = requestAnimationFrame(frame);
    };
    const onResize = () => {
      resize();
      if (still) frame();
    };

    resize();
    frame();
    window.addEventListener("resize", onResize);
    window.addEventListener("pointermove", onMove);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onResize);
      window.removeEventListener("pointermove", onMove);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);

  return <canvas ref={ref} className="login-net" />;
}
