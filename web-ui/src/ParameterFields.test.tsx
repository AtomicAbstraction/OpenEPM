import { useState } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import {
  ParameterFields,
  definitionParameterSchema,
  parameterInputError,
} from "./ParameterFields";

function Form({
  schema,
  initial = "{}",
}: {
  schema?: Record<string, unknown>;
  initial?: string;
}) {
  const [value, setValue] = useState(initial);
  return (
    <>
      <ParameterFields
        label="Rule parameters"
        advancedLabel="Advanced bindings"
        schema={schema}
        value={value}
        onChange={setValue}
      />
      <output aria-label="Submitted bindings">{value}</output>
      <output aria-label="Input error">
        {parameterInputError(value, schema)}
      </output>
    </>
  );
}

it("uses declared fields without applying sample values and preserves exact decimal strings", () => {
  render(
    <Form
      schema={definitionParameterSchema([
        { name: "amount", type: "Amount", sample: "1" },
        { name: "ratio", type: "Ratio", sample: "2" },
        { name: "enabled", type: "Boolean", sample: true },
        {
          name: "scenario",
          type: "Member",
          dimensionId: "Scenario",
          sample: "Budget",
        },
      ])}
    />,
  );
  expect(screen.getByLabelText("Submitted bindings")).toHaveTextContent("{}");
  expect(screen.getByLabelText("Input error")).toHaveTextContent(
    "amount: provide a value",
  );
  fireEvent.change(screen.getByLabelText("amount"), {
    target: { value: "99999999999999999999.12345678" },
  });
  fireEvent.change(screen.getByLabelText("ratio"), {
    target: { value: "1.123456789012" },
  });
  fireEvent.change(screen.getByLabelText("enabled"), {
    target: { value: "false" },
  });
  fireEvent.change(screen.getByLabelText("scenario"), {
    target: { value: "Budget" },
  });
  expect(
    JSON.parse(screen.getByLabelText("Submitted bindings").textContent!),
  ).toEqual({
    amount: "99999999999999999999.12345678",
    ratio: "1.123456789012",
    enabled: false,
    scenario: "Budget",
  });
  expect(screen.getByLabelText("Input error")).toBeEmptyDOMElement();
});

it("keeps saved member-list identity, version and nested bindings in their server types", () => {
  render(
    <Form
      schema={definitionParameterSchema([
        {
          name: "entities",
          type: "MemberList",
          dimensionId: "Entity",
          sample: ["France"],
        },
      ])}
    />,
  );
  fireEvent.change(screen.getByLabelText("entities.listId"), {
    target: { value: "europe" },
  });
  expect(
    JSON.parse(screen.getByLabelText("Submitted bindings").textContent!),
  ).toEqual({
    entities: { listId: "europe", parameters: {} },
  });
  expect(screen.getByLabelText("Input error")).toBeEmptyDOMElement();
  fireEvent.change(screen.getByLabelText("entities.parameters"), {
    target: { value: '{"region":"Europe"}' },
  });
  expect(
    JSON.parse(screen.getByLabelText("Submitted bindings").textContent!),
  ).toEqual({
    entities: {
      listId: "europe",
      parameters: { region: "Europe" },
    },
  });
});

it("honors source enum value types and allows an optional boolean to be unset", () => {
  render(
    <Form
      schema={{
        type: "object",
        properties: { mode: { enum: [1, "one"] }, flag: { type: "boolean" } },
      }}
    />,
  );
  fireEvent.change(screen.getByLabelText("mode"), {
    target: { value: '"one"' },
  });
  fireEvent.change(screen.getByLabelText("flag"), {
    target: { value: "true" },
  });
  fireEvent.change(screen.getByLabelText("flag"), { target: { value: "" } });
  expect(screen.getByLabelText("Submitted bindings")).toHaveTextContent(
    '{"mode":"one"}',
  );
  fireEvent.change(screen.getByLabelText("mode"), { target: { value: "1" } });
  expect(screen.getByLabelText("Submitted bindings")).toHaveTextContent(
    '{"mode":1}',
  );
});

it("preserves numeric typing drafts and refuses unsafe integers without rounding them", () => {
  render(
    <Form
      schema={{ type: "object", properties: { factor: { type: "number" } } }}
    />,
  );
  fireEvent.change(screen.getByLabelText("factor"), {
    target: { value: "1." },
  });
  expect(screen.getByLabelText("factor")).toHaveValue("1.");
  fireEvent.change(screen.getByLabelText("factor"), {
    target: { value: "1.25" },
  });
  expect(screen.getByLabelText("Submitted bindings")).toHaveTextContent(
    '{"factor":"1.25"}',
  );
  expect(screen.getByLabelText("Input error")).toHaveTextContent(
    "Declare exact decimal parameters as strings",
  );
  fireEvent.change(screen.getByLabelText("factor"), {
    target: { value: "9007199254740993" },
  });
  expect(screen.getByLabelText("Submitted bindings")).toHaveTextContent(
    '{"factor":"9007199254740993"}',
  );
  expect(screen.getByLabelText("Input error")).not.toBeEmptyDOMElement();
});

it("retains malformed advanced input for correction instead of silently clearing it", () => {
  render(
    <Form
      initial="{"
      schema={{ type: "object", properties: { factor: { type: "string" } } }}
    />,
  );
  expect(screen.getByLabelText("Advanced bindings")).toHaveValue("{");
  expect(screen.getByLabelText("Input error")).toHaveTextContent(
    "valid object",
  );
  fireEvent.change(screen.getByLabelText("Advanced bindings"), {
    target: { value: '{"factor":"2"}' },
  });
  expect(screen.getByLabelText("factor")).toHaveValue("2");
  expect(screen.getByLabelText("Input error")).toBeEmptyDOMElement();
});

it("keeps near-integer and underflow drafts exact and blocks advanced JSON rounding", () => {
  const schema = {
    type: "object",
    properties: { factor: { type: "number" }, note: { type: "string" } },
  };
  render(<Form schema={schema} />);
  for (const value of [
    "0.999999999999999999999",
    "9007199254740991.1",
    "1e-1000",
  ]) {
    fireEvent.change(screen.getByLabelText("factor"), { target: { value } });
    expect(screen.getByLabelText("factor")).toHaveValue(value);
    expect(screen.getByLabelText("Submitted bindings")).toHaveTextContent(
      JSON.stringify({ factor: value }),
    );
    expect(screen.getByLabelText("Input error")).not.toBeEmptyDOMElement();
  }
  const original = '{"factor":0.999999999999999999999,"note":"keep"}';
  fireEvent.change(screen.getByLabelText("Advanced bindings"), {
    target: { value: original },
  });
  expect(screen.getByLabelText("Submitted bindings")).toHaveTextContent(
    original,
  );
  expect(screen.getByLabelText("Input error")).toHaveTextContent(
    "exact safe integers",
  );
  expect(screen.queryByLabelText("note")).toBeNull();
  fireEvent.change(screen.getByLabelText("Advanced bindings"), {
    target: { value: '{"factor":1,"note":"keep"}' },
  });
  expect(screen.getByLabelText("factor")).toHaveValue("1");
  expect(screen.getByLabelText("note")).toHaveValue("keep");
  expect(screen.getByLabelText("Input error")).toBeEmptyDOMElement();
});

it("keeps invalid array drafts visible and blocks their submission as strings", () => {
  const schema = {
    type: "object",
    properties: {
      items: { type: "array", items: { type: "integer" } },
    },
  };
  render(<Form schema={schema} />);
  for (const value of ["[0.999999999999999999999]", "[1e-1000]", "[", "true"]) {
    fireEvent.change(screen.getByLabelText("items"), { target: { value } });
    expect(screen.getByLabelText("items")).toHaveValue(value);
    expect(screen.getByLabelText("Input error")).toHaveTextContent(
      "enter an array",
    );
  }
  fireEvent.change(screen.getByLabelText("items"), {
    target: { value: '["wrong"]' },
  });
  expect(screen.getByLabelText("Input error")).toHaveTextContent(
    "Parameters.items[0]",
  );
  fireEvent.change(screen.getByLabelText("items"), {
    target: { value: "[1,2]" },
  });
  expect(screen.getByLabelText("Submitted bindings")).toHaveTextContent(
    '{"items":[1,2]}',
  );
  expect(screen.getByLabelText("Input error")).toBeEmptyDOMElement();
});
