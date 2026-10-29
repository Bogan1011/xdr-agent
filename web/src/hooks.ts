import { useCallback, useEffect, useRef, useState } from "react";

// usePoll loads data now and every intervalMs while the tab is visible.
// Responses that arrive after the deps changed (or after unmount) are dropped,
// polls never overlap, and unchanged payloads don't re-render the page.
export function usePoll<T>(load: () => Promise<T>, intervalMs: number, deps: unknown[] = []) {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<string>("");
  const loadRef = useRef(load);
  loadRef.current = load;
  const gen = useRef(0);
  const busy = useRef(false);
  const last = useRef<string>("");

  const refresh = useCallback(() => {
    const mine = gen.current;
    busy.current = true;
    loadRef
      .current()
      .then((d) => {
        if (mine !== gen.current) return;
        let key: string | undefined;
        try {
          key = JSON.stringify(d);
        } catch {
          key = undefined;
        }
        if (key === undefined || key !== last.current) {
          last.current = key ?? "";
          setData(d);
        }
        setError("");
      })
      .catch((e: Error) => {
        if (mine === gen.current) setError(e.message);
      })
      .finally(() => {
        if (mine === gen.current) busy.current = false;
      });
  }, []);

  useEffect(() => {
    gen.current++;
    busy.current = false;
    refresh();
    if (!intervalMs) return () => void gen.current++;
    const tick = () => {
      if (document.visibilityState === "visible" && !busy.current) refresh();
    };
    const t = setInterval(tick, intervalMs);
    document.addEventListener("visibilitychange", tick);
    return () => {
      gen.current++;
      clearInterval(t);
      document.removeEventListener("visibilitychange", tick);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refresh, intervalMs, ...deps]);

  return { data, error, refresh };
}
