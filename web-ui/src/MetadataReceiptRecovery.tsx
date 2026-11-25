import { useEffect, useRef } from "react";

type ReceiptRecovery = {
  pending: boolean;
  busy: boolean;
  message: string;
  canCheckReceipt: boolean;
  retryReady: boolean;
  canCloseRecovery: boolean;
  checkReceipt: () => Promise<void>;
  retry: () => Promise<void>;
};

export function focusWhenInteractive(element: HTMLElement | null) {
  if (!element) return;
  if (!element.closest("[inert]")) {
    element.focus();
    return;
  }
  const document = element.ownerDocument;
  const previous = document.activeElement;
  const observer = new MutationObserver(() => {
    if (!element.isConnected) {
      observer.disconnect();
    } else if (!element.closest("[inert]")) {
      observer.disconnect();
      const active = document.activeElement;
      if (active === previous || active === document.body) element.focus();
    }
  });
  for (
    let ancestor = element.parentElement;
    ancestor;
    ancestor = ancestor.parentElement
  ) {
    observer.observe(ancestor, {
      attributes: true,
      attributeFilter: ["inert"],
    });
  }
  return () => observer.disconnect();
}

export function MetadataReceiptRecovery({
  object,
  recovery,
  onClose,
  copyReceiptCheck,
}: {
  object:
    | "planning policy"
    | "hierarchy"
    | "hierarchy build"
    | "placement"
    | "relationship"
    | "security string"
    | "security tag"
    | "metadata";
  recovery: ReceiptRecovery;
  onClose: () => void;
  copyReceiptCheck?: () => Promise<void>;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (recovery.pending && !recovery.busy)
      return focusWhenInteractive(heading.current);
  }, [recovery.pending, recovery.busy]);

  if (!recovery.pending)
    return recovery.message ? (
      <div className="inline-error" role="alert">
        {recovery.message}
      </div>
    ) : null;

  const subject = object === "hierarchy build" ? object : `${object} change`;
  const label = subject[0].toUpperCase() + subject.slice(1);
  return (
    <section
      className="metadata-changeset-review"
      aria-label={`${label} status`}
    >
      <h4 tabIndex={-1} ref={heading}>
        {label} awaiting confirmation
      </h4>
      <p role="status">
        {recovery.message ||
          (recovery.canCheckReceipt
            ? `Check the original receipt to confirm whether the ${subject} was applied.`
            : "Receipt checks require current application access.")}
      </p>
      <button
        type="button"
        disabled={recovery.busy || !recovery.canCheckReceipt}
        onClick={() => void recovery.checkReceipt()}
      >
        Check original {object} receipt
      </button>
      {copyReceiptCheck && (
        <button
          type="button"
          disabled={recovery.busy || !recovery.canCheckReceipt}
          onClick={() => void copyReceiptCheck()}
        >
          Copy receipt check for MCP
        </button>
      )}
      {recovery.retryReady && (
        <button
          type="button"
          disabled={recovery.busy}
          onClick={() => void recovery.retry()}
        >
          Retry original {subject}
        </button>
      )}
      {recovery.canCloseRecovery && (
        <button type="button" disabled={recovery.busy} onClick={onClose}>
          Close unconfirmed {subject}
        </button>
      )}
    </section>
  );
}
