import { useId } from "react";

// Logo is the Ironsight XDR mark: an eye watching from inside a shield.
// With animated set (the login page), the iris glows and the scan ring turns.
export function Logo({ size = 32, animated = false }: { size?: number; animated?: boolean }) {
  const id = useId().replace(/:/g, "");
  const edge = `ls-edge-${id}`;
  const fill = `ls-fill-${id}`;
  const iris = `ls-iris-${id}`;
  return (
    <svg
      className={"logo" + (animated ? " logo-anim" : "")}
      viewBox="0 0 48 48"
      width={size}
      height={size}
      role="img"
      aria-label="Ironsight XDR"
    >
      <defs>
        <linearGradient id={edge} x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#ff8fb3" />
          <stop offset="0.55" stopColor="#ffb37a" />
          <stop offset="1" stopColor="#b69cff" />
        </linearGradient>
        <linearGradient id={fill} x1="24" y1="3" x2="24" y2="45" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#3a1f3d" />
          <stop offset="1" stopColor="#140d1f" />
        </linearGradient>
        <radialGradient id={iris} cx="0.42" cy="0.38" r="0.7">
          <stop offset="0" stopColor="#ffd6a8" />
          <stop offset="0.45" stopColor="#ff7aa8" />
          <stop offset="1" stopColor="#8b5cf6" />
        </radialGradient>
      </defs>
      <path
        d="M24 3.5 41 10v12.2C41 33 33.6 40.8 24 44.5 14.4 40.8 7 33 7 22.2V10z"
        fill={`url(#${fill})`}
        stroke={`url(#${edge})`}
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      <path
        className="logo-lid"
        d="M11.5 24c3.6-5.6 7.8-8.6 12.5-8.6s8.9 3 12.5 8.6c-3.6 5.6-7.8 8.6-12.5 8.6S15.1 29.6 11.5 24z"
        fill="none"
        stroke={`url(#${edge})`}
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <circle className="logo-ring" cx="24" cy="24" r="7.6" fill="none" stroke="#ffb37a" strokeOpacity="0.55" strokeWidth="1" strokeDasharray="3 2.6" />
      <circle className="logo-iris" cx="24" cy="24" r="5.2" fill={`url(#${iris})`} />
      <circle cx="24" cy="24" r="2" fill="#140d1f" />
      <circle cx="25.7" cy="22.3" r="0.9" fill="#fff" fillOpacity="0.9" />
    </svg>
  );
}

// Wordmark is the logo with the product name beside it.
export function Wordmark({ size = 30, animated = false, sub = true }: { size?: number; animated?: boolean; sub?: boolean }) {
  return (
    <span className="wordmark">
      <Logo size={size} animated={animated} />
      <span className="wordmark-text">
        <span className="wordmark-name">Ironsight<b>XDR</b></span>
        {sub && <span className="wordmark-sub">Detect · Respond · Protect</span>}
      </span>
    </span>
  );
}
