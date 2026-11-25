import { act, renderHook } from "@testing-library/react";
import { usePreservedDraft } from "./unsaved-work";

/** Exercise the real bounded registry using small independent recovery owners. */
export function fillRecoverySlots(count = 24) {
  return Array.from({ length: count }, (_, index) => {
    const mounted = renderHook(() =>
      usePreservedDraft(
        "capacity-test",
        `app-${index}`,
        "recovery",
        "Unresolved test request",
        false,
        { packet: "" },
        () => undefined,
      ),
    );
    const handle = mounted.result.current;
    let lease: NonNullable<typeof handle.lease>;
    act(() => {
      lease = handle.retain({ packet: `original-${index}` });
    });
    mounted.unmount();
    return () => act(() => handle.release(lease, { packet: "" }));
  });
}
