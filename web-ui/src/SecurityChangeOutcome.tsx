import { RequesterBenefitDetails } from "./RequesterBenefit";
import type { useApplicationSecurityChange } from "./application-security-change";

export function SecurityChangeOutcome({
  securityChange,
  busy,
}: {
  securityChange: ReturnType<typeof useApplicationSecurityChange>;
  busy: boolean;
}) {
  return securityChange.original ? (
    <section className="operation-notice" aria-label="Original security change">
      <p role="status">
        {securityChange.busy
          ? "Checking the original security change…"
          : securityChange.message ||
            "The original security change is unconfirmed."}
      </p>
      {!securityChange.canReadReceipt && (
        <p>The current application catalogue does not offer a receipt check.</p>
      )}
      <button
        disabled={busy || !securityChange.canReadReceipt}
        onClick={() => void securityChange.checkReceipt()}
      >
        Check original security change
      </button>
      {securityChange.canReadReceipt && (
        <button
          disabled={busy}
          onClick={() => void securityChange.copyReceiptCheck()}
        >
          Copy receipt check for MCP
        </button>
      )}
      {securityChange.canRetry && (
        <button
          disabled={busy}
          onClick={() => {
            if (window.confirm("Retry the exact original security change?"))
              void securityChange.retry();
          }}
        >
          Retry original security change
        </button>
      )}
    </section>
  ) : securityChange.message ? (
    <div className="inline-error" role="alert">
      {securityChange.message}
    </div>
  ) : securityChange.requesterBenefit ? (
    <RequesterBenefitDetails evidence={securityChange.requesterBenefit} />
  ) : securityChange.requesterBenefitUnavailable ? (
    <p role="status">
      The change was recorded. Its requester grant details could not be
      verified.
    </p>
  ) : null;
}
