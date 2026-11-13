import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { PythonImpactView } from "./PythonImpactView";

const digest = "a".repeat(64);
function artifact(rows: unknown[]) {
  return JSON.stringify({
    format: "openepm-python-impact-v1",
    status: "complete",
    sourceDigest: digest,
    businessDataChanged: false,
    baseline: { data_revision: 12, metadata_revision: 4, policy_revision: 2 },
    counts: {
      selected: rows.length,
      changed: rows.length,
      created: 0,
      cleared: 0,
    },
    rows,
  });
}
it("renders each side independently and preserves decimal precision across numeric, text and detail transitions", async () => {
  render(
    <PythonImpactView
      complete
      sourceDigest={digest}
      text={artifact([
        {
          seriesKey: "1",
          members: { Account: "Revenue" },
          before: { present: true, amount: "99999999999999999.12345678" },
          after: {
            present: true,
            kind: "text",
            text: "<script>text</script>",
            amount: null,
          },
          delta: null,
        },
        {
          seriesKey: "2",
          members: { Account: "Costs" },
          before: { present: false, amount: null },
          after: {
            present: true,
            kind: "line-detail",
            amount: "1.00000001",
            items: [{ description: "A", amount: "1.00000001" }],
          },
          delta: "1.00000001",
        },
      ])}
    />,
  );
  expect(screen.getByText("99999999999999999.12345678")).toBeInTheDocument();
  expect(screen.getByText("<script>text</script>")).toBeInTheDocument();
  expect(document.querySelector("script")).toBeNull();
  expect(screen.getByText("Not applicable")).toBeInTheDocument();
  expect(screen.getByText("Not present")).toBeInTheDocument();
  fireEvent.click(screen.getByText("Detail total: 1.00000001 (1 lines)"));
  expect(await screen.findByText("A: 1.00000001")).toBeInTheDocument();
});

it("pages complete cell effects and never presents a partial or foreign-source artifact as complete", () => {
  const rows = Array.from({ length: 51 }, (_, index) => ({
    seriesKey: String(index),
    members: { axis: `member-${index}` },
    before: { present: false, amount: null },
    after: { present: true, amount: "1.00000000" },
    delta: "1.00000000",
  }));
  const text = artifact(rows);
  const { rerender } = render(
    <PythonImpactView complete={false} sourceDigest={digest} text={text} />,
  );
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
  rerender(
    <PythonImpactView complete sourceDigest={"b".repeat(64)} text={text} />,
  );
  expect(screen.getByRole("alert")).toHaveTextContent("cannot be rendered");
  rerender(<PythonImpactView complete sourceDigest={digest} text={text} />);
  expect(screen.getAllByRole("row")).toHaveLength(51);
  expect(
    screen.getByRole("region", {
      name: "Before and after effects scroll area",
    }),
  ).toHaveAttribute("tabindex", "0");
  fireEvent.click(screen.getByRole("button", { name: "Next cells" }));
  expect(screen.getAllByRole("row")).toHaveLength(2);
  expect(screen.getByText("axis: member-50")).toBeInTheDocument();
});
it("renders bounded typed member-list and calculation results without persisting or rounding values", () => {
  const base = JSON.parse(artifact([]));
  const { rerender } = render(
    <PythonImpactView
      complete
      sourceDigest={digest}
      text={JSON.stringify({
        ...base,
        definitionResult: {
          kind: "MemberList",
          definitionId: "list",
          dimensionId: "Product",
          memberIds: Array.from(
            { length: 101 },
            (_, index) => `selected-${index}`,
          ),
          memberCount: 101,
          bindings: {},
        },
      })}
    />,
  );
  expect(screen.getAllByRole("listitem")).toHaveLength(100);
  fireEvent.click(screen.getByRole("button", { name: "Next tested members" }));
  expect(screen.getByText("selected-100")).toBeInTheDocument();
  rerender(
    <PythonImpactView
      complete
      sourceDigest={digest}
      text={JSON.stringify({
        ...base,
        definitionResult: {
          kind: "CalculatedMember",
          definitionId: "calc",
          evaluation: "dynamic",
          persisted: false,
          rowCount: 1,
          bindings: {},
          rows: [
            {
              members: { Account: "Margin" },
              value: {
                type: "AmountLiteral",
                decimal: "99999999999999999.12345678",
              },
            },
          ],
        },
      })}
    />,
  );
  expect(screen.getByText("99999999999999999.12345678")).toBeInTheDocument();
  expect(screen.getByText(/no persisted result/)).toBeInTheDocument();
});

it("distinguishes calculation generations from raw cells at the same coordinate without rounding ratios", () => {
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    render(
      <PythonImpactView
        complete
        sourceDigest={digest}
        text={artifact([
          {
            seriesKey: "same",
            members: { Account: "Margin" },
            before: { present: false, amount: null },
            after: { present: true, amount: "2.00000000" },
            delta: "2.00000000",
          },
          {
            storage: "calculation",
            resultKey: "margin",
            beforeResultStateToken: "a".repeat(64),
            seriesKey: "same",
            members: { Account: "Margin" },
            before: {
              present: true,
              amount: "0.123456789012",
              valueType: "RatioLiteral",
            },
            after: { present: false, amount: null },
            delta: "-0.123456789012",
          },
          {
            storage: "calculation",
            resultKey: "other",
            seriesKey: "same",
            members: { Account: "Margin" },
            before: { present: false, amount: null },
            after: {
              present: true,
              amount: "0.234567890123",
              valueType: "RatioLiteral",
            },
            delta: "0.234567890123",
          },
        ])}
      />,
    );
    expect(screen.getByText("Raw cell")).toBeInTheDocument();
    expect(screen.getAllByText("Calculation result")).toHaveLength(2);
    expect(screen.queryByText("margin")).not.toBeInTheDocument();
    expect(screen.queryByText("other")).not.toBeInTheDocument();
    expect(screen.getByText("0.123456789012 (ratio)")).toBeInTheDocument();
    expect(screen.getByText("0.234567890123 (ratio)")).toBeInTheDocument();
    expect(screen.getAllByRole("row")).toHaveLength(4);
    expect(consoleError).not.toHaveBeenCalled();
  } finally {
    consoleError.mockRestore();
  }
});

it("renders an application-rule result without exposing its backend identity", () => {
  render(
    <PythonImpactView
      complete
      sourceDigest={digest}
      text={JSON.stringify({
        ...JSON.parse(artifact([])),
        definitionResult: {
          kind: "ApplicationRule",
          definitionId: "margin",
          bindings: {},
        },
      })}
    />,
  );
  expect(
    screen.getByRole("heading", { name: "ApplicationRule test result" }),
  ).toBeInTheDocument();
  expect(screen.queryByText("margin")).not.toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

it("shows each typed currency beside its exact amount and keeps cross-currency delta inapplicable", () => {
  const amount = "99999999999999999.12345678";
  render(
    <PythonImpactView
      complete
      sourceDigest={digest}
      text={artifact([
        {
          storage: "calculation",
          resultKey: "closing",
          seriesKey: "one",
          members: { Account: "Closing" },
          before: {
            present: true,
            amount,
            valueType: "AmountLiteral",
            outputUnit: { dimensionId: "Currency", memberId: "USD" },
          },
          after: {
            present: true,
            amount,
            valueType: "AmountLiteral",
            outputUnit: { dimensionId: "Currency", memberId: "EUR" },
          },
          delta: null,
        },
      ])}
    />,
  );
  expect(screen.getByText(`${amount} (Currency: USD)`)).toBeInTheDocument();
  expect(screen.getByText(`${amount} (Currency: EUR)`)).toBeInTheDocument();
  expect(screen.getByText("Not applicable")).toBeInTheDocument();
});

it.each([{ memberId: "USD" }, { dimensionId: "Currency", memberId: null }])(
  "does not silently display an amount with malformed unit %j as unitless",
  (outputUnit) => {
    render(
      <PythonImpactView
        complete
        sourceDigest={digest}
        text={artifact([
          {
            storage: "calculation",
            resultKey: "closing",
            seriesKey: "one",
            members: { Account: "Closing" },
            before: { present: false, amount: null },
            after: { present: true, amount: "7.00000000", outputUnit },
            delta: null,
          },
        ])}
      />,
    );
    expect(screen.getByText("Unrecognized value")).toBeInTheDocument();
    expect(screen.queryByText("7.00000000")).not.toBeInTheDocument();
  },
);
