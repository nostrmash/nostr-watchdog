import type { JsonSocket } from "./alerts/relay";
import type { FetchLike } from "./types";

export interface Dependencies {
  fetch: FetchLike;
  now: () => number;
  connectRelay?: (url: string) => Promise<JsonSocket>;
}

export function defaultDependencies(now: () => number = () => Date.now()): Dependencies {
  return {
    fetch: (input, init) => fetch(input, init),
    now,
  };
}
