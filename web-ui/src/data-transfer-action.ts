import type { MouseEvent } from "react";

export function transferAction(
  blocked: boolean,
  run: (origin: HTMLButtonElement) => void | Promise<void>,
) {
  return {
    type: "button" as const,
    "aria-disabled": blocked || undefined,
    // A blocked control leaves the tab order and preserves existing focus.
    tabIndex: blocked ? -1 : undefined,
    onClick: (event: MouseEvent<HTMLButtonElement>) => {
      if (!blocked) void run(event.currentTarget);
    },
  };
}
