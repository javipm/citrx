import { useEffect, useState } from "react";
import { SPINNER_FRAMES } from "../types.js";

/**
 * React hook that returns the current spinner frame character.
 *
 * Cycles through `SPINNER_FRAMES` on a 120 ms interval while `active` is
 * `true`. Resets to frame 0 and clears the interval when `active` becomes
 * `false`. The interval is also cleared on unmount via the effect cleanup.
 *
 * @param active - When `true` the spinner animates; when `false` it stops.
 * @returns The current frame character (e.g. `"⠋"`), or `"-"` as a fallback.
 */
export function useSpinner(active: boolean): string {
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    if (!active) {
      setFrame(0);
      return;
    }

    const timer = setInterval(() => {
      setFrame((value) => (value + 1) % SPINNER_FRAMES.length);
    }, 120);

    return () => {
      clearInterval(timer);
    };
  }, [active]);

  return SPINNER_FRAMES[frame] ?? "-";
}
