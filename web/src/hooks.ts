import { useCallback, useEffect, useRef, useState } from "react";

// usePoll loads data now and every intervalMs while the tab is visible.
export function usePoll<T>(load: () => Promise<T>, intervalMs: number, deps: unknown[] = []) {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<string>("");
  const loadRef = useRef(load);
  loadRef.current = load;

  const refresh = useCallback(() => {
    loadRef
      .current()
      .then((d) => {
        setData(d);
        setError("");
      })
      .catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    refresh();
    if (!intervalMs) return;
    const t = setInterval(() => {
      if (document.visibilityState === "visible") refresh();
    }, intervalMs);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refresh, intervalMs, ...deps]);

  return { data, error, refresh };
}
