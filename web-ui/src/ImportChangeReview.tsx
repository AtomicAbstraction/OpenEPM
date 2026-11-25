type Value = {
  present: boolean;
  amount?: string;
  text?: string;
  items?: Array<{ description: string; amount: string }>;
};
type Example = {
  action: "set" | "clear";
  members: Record<string, string>;
  valueKind: "numeric" | "text" | "detail";
  sourceRef: string | null;
  before: Value;
  after: Value;
  companionChanges?: Array<{
    valueKind: "numeric" | "text" | "detail";
    before: Value;
    after: Value;
  }>;
};
export type ImportReview = {
  format: "openepm-source-change-review-v1";
  mode: string;
  scopeMembers: Record<string, string>;
  scopeAll: boolean;
  periodSelection: unknown;
  metadataRevision: number;
  dataRevision: number;
  commitRevision: number;
  sampleLimitPerAction: number;
  setsComplete: boolean;
  clearsComplete: boolean;
  readRestricted: boolean;
  examples: Example[];
};

const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const members = (value: unknown): value is Record<string, string> =>
  object(value) &&
  Object.entries(value).every(
    ([key, item]) =>
      key.length > 0 && typeof item === "string" && item.length > 0,
  );
const decimal = (value: unknown) =>
  typeof value === "string" && /^-?\d+(?:\.\d+)?$/.test(value);
function validValue(value: unknown, kind: unknown): value is Value {
  if (!object(value) || typeof value.present !== "boolean") return false;
  if (!value.present) return Object.keys(value).length === 1;
  if (kind === "text")
    return Object.keys(value).length === 2 && typeof value.text === "string";
  if (kind === "numeric")
    return Object.keys(value).length === 2 && decimal(value.amount);
  return (
    Object.keys(value).length === 3 &&
    decimal(value.amount) &&
    Array.isArray(value.items) &&
    value.items.length <= 500 &&
    value.items.every(
      (item) =>
        object(item) &&
        Object.keys(item).length === 2 &&
        typeof item.description === "string" &&
        decimal(item.amount),
    )
  );
}

export function validateImportReview(
  value: unknown,
  mode: string,
  counts: { setCount: number; clearCount: number },
  factDimensions?: readonly string[],
): ImportReview {
  if (
    !object(value) ||
    value.format !== "openepm-source-change-review-v1" ||
    value.mode !== mode ||
    !members(value.scopeMembers) ||
    typeof value.scopeAll !== "boolean" ||
    ![value.metadataRevision, value.dataRevision, value.commitRevision].every(
      (pin) => Number.isSafeInteger(pin) && Number(pin) >= 0,
    ) ||
    value.sampleLimitPerAction !== 20 ||
    ![value.setsComplete, value.clearsComplete, value.readRestricted].every(
      (flag) => typeof flag === "boolean",
    ) ||
    !Array.isArray(value.examples) ||
    value.examples.length > 40 ||
    !value.examples.every(
      (item) =>
        object(item) &&
        ["set", "clear"].includes(String(item.action)) &&
        members(item.members) &&
        Object.keys(item.members).length > 0 &&
        ["numeric", "text", "detail"].includes(String(item.valueKind)) &&
        validValue(item.before, item.valueKind) &&
        validValue(item.after, item.valueKind) &&
        (item.companionChanges === undefined ||
          (Array.isArray(item.companionChanges) &&
            item.companionChanges.length <= 2 &&
            item.companionChanges.every(
              (change) =>
                object(change) &&
                ["numeric", "text", "detail"].includes(
                  String(change.valueKind),
                ) &&
                validValue(change.before, change.valueKind) &&
                validValue(change.after, change.valueKind),
            ))) &&
        (item.action === "set"
          ? typeof item.sourceRef === "string" &&
            item.sourceRef.length > 0 &&
            item.after.present
          : item.sourceRef === null &&
            item.before.present &&
            !item.after.present),
    )
  )
    throw new Error("INVALID_SOURCE_CHANGE_REVIEW");
  const fixedScope = Object.entries(value.scopeMembers);
  if (
    value.examples.some((item) =>
      fixedScope.some(
        ([axis, member]) =>
          !Object.hasOwn(item.members, axis) || item.members[axis] !== member,
      ),
    )
  )
    throw new Error(
      "A change example falls outside the reviewed destination scope.",
    );
  if (
    factDimensions &&
    value.examples.some(
      ({ members }) =>
        Object.keys(members).length !== factDimensions.length ||
        factDimensions.some((axis) => !Object.hasOwn(members, axis)),
    )
  )
    throw new Error(
      "A change example does not match the reviewed fact dimensions.",
    );
  if (mode === "merge" && counts.clearCount !== 0)
    throw new Error("A merge preview cannot clear omitted values.");
  const sets = value.examples.filter((item) => item.action === "set").length;
  const clears = value.examples.length - sets;
  if (
    sets > 20 ||
    clears > 20 ||
    sets > counts.setCount ||
    clears > counts.clearCount ||
    value.setsComplete !== (sets === counts.setCount) ||
    value.clearsComplete !== (clears === counts.clearCount)
  )
    throw new Error("INVALID_SOURCE_CHANGE_REVIEW_COMPLETENESS");
  const identities = value.examples.map((item) =>
    JSON.stringify([
      item.action,
      item.valueKind,
      Object.entries(item.members).sort(([left], [right]) =>
        left.localeCompare(right),
      ),
    ]),
  );
  if (
    new Set(identities).size !== identities.length ||
    value.examples.some((item) => {
      const kinds = (item.companionChanges || []).map(
        (change: { valueKind: string }) => change.valueKind,
      );
      return (
        kinds.includes(item.valueKind) || new Set(kinds).size !== kinds.length
      );
    })
  )
    throw new Error("INVALID_SOURCE_CHANGE_REVIEW_DUPLICATE");
  return value as ImportReview;
}

function valueText(value: Value, kind: string): string {
  if (!value.present) return "Absent";
  if (kind === "text")
    return value.text === "" ? "Empty text (present)" : value.text!;
  if (kind === "detail")
    return `${value.amount} · ${value.items!.length} detail items`;
  return value.amount!;
}

function ReviewedValue({ value, kind }: { value: Value; kind: string }) {
  return (
    <>
      {valueText(value, kind)}
      {value.present && kind === "detail" && (
        <details>
          <summary>Supporting detail items</summary>
          <ul>
            {value.items!.map((item, index) => (
              <li key={index}>
                {item.description}: {item.amount}
              </li>
            ))}
          </ul>
        </details>
      )}
    </>
  );
}

function coordinateText(coordinate: Record<string, string>) {
  return Object.entries(coordinate)
    .map(([dimension, member]) => `${dimension}: ${member}`)
    .join("; ");
}

export function ImportChangeReview({
  review,
  scenarioSource,
}: {
  review: ImportReview | null;
  scenarioSource?: { dimensionId: string; memberId: string };
}) {
  if (!review)
    return (
      <p role="status">
        Preview the current input to inspect authorized before/after examples.
        Counts alone do not describe individual changes.
      </p>
    );
  return (
    <section
      aria-label={
        scenarioSource
          ? "Scenario copy change examples"
          : "Import change examples"
      }
    >
      <p>
        {review.mode === "replace"
          ? "Replace clears omitted values only within the reviewed scope."
          : "Merge preserves omitted values."}{" "}
        Stored input values are shown exactly; zero, empty text and absence are
        distinct.
      </p>
      <p>
        Target:{" "}
        {review.scopeAll
          ? "whole application"
          : coordinateText(review.scopeMembers)}
        .{" "}
        {review.periodSelection != null
          ? "An additional period selection applies to this intent."
          : ""}
      </p>
      <p>
        {review.setsComplete && review.clearsComplete
          ? "All changes are shown."
          : `Bounded examples: at most ${review.sampleLimitPerAction} sets and ${review.sampleLimitPerAction} clears. Use the full counts above to understand scope.`}{" "}
        {review.readRestricted
          ? "Some examples are withheld by current read permissions."
          : ""}
      </p>
      <div className="react-grid-scroll">
        <table className="react-cube-grid">
          <caption>
            Before and after at metadata revision {review.metadataRevision},
            data revision {review.dataRevision}, commit revision{" "}
            {review.commitRevision}
          </caption>
          <thead>
            <tr>
              <th scope="col">Action</th>
              <th scope="col">
                {scenarioSource ? "Destination coordinate" : "Coordinate"}
              </th>
              <th scope="col">Value kind</th>
              <th scope="col">Before</th>
              <th scope="col">After</th>
              <th scope="col">
                {scenarioSource ? "Source coordinate" : "Source reference"}
              </th>
            </tr>
          </thead>
          <tbody>
            {review.examples.map((item, index) => (
              <tr key={index}>
                <td>
                  {item.action === "clear"
                    ? "Clear omitted value"
                    : item.before.present
                      ? "Replace supplied value"
                      : "Add supplied value"}
                </td>
                <td>{coordinateText(item.members)}</td>
                <td>{item.valueKind}</td>
                <td>
                  <ReviewedValue value={item.before} kind={item.valueKind} />
                  {item.companionChanges?.map((change, i) => (
                    <div key={i}>
                      Linked {change.valueKind}:{" "}
                      <ReviewedValue
                        value={change.before}
                        kind={change.valueKind}
                      />
                    </div>
                  ))}
                </td>
                <td>
                  <ReviewedValue value={item.after} kind={item.valueKind} />
                  {item.companionChanges?.map((change, i) => (
                    <div key={i}>
                      Linked {change.valueKind}:{" "}
                      <ReviewedValue
                        value={change.after}
                        kind={change.valueKind}
                      />
                    </div>
                  ))}
                </td>
                <td>
                  {scenarioSource ? (
                    item.action === "clear" ? (
                      "Omitted from source"
                    ) : (
                      <>
                        {coordinateText({
                          ...item.members,
                          [scenarioSource.dimensionId]: scenarioSource.memberId,
                        })}
                        {item.sourceRef && (
                          <details>
                            <summary>Source reference</summary>
                            <code>{item.sourceRef}</code>
                          </details>
                        )}
                      </>
                    )
                  ) : (
                    (item.sourceRef ?? "Omitted from input")
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
