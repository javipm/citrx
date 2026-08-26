import type { Dispatch, SetStateAction } from "react";

import type { ActiveAbortEntry } from "../types.js";

export type ActiveAbortSetter = Dispatch<SetStateAction<ActiveAbortEntry | undefined>>;

export function clearAbortIfCurrent(
  setActiveAbort: ActiveAbortSetter | undefined,
  controller: AbortController
): void {
  setActiveAbort?.((prev) => (prev?.controller === controller ? undefined : prev));
}
