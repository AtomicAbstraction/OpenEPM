import { expect, it } from "vitest";
import {
  exactIntegerInput,
  InexactParameterNumber,
  parseParameterJson,
} from "./exact-parameters";

it.each([
  ["1.000", 1],
  ["1000e-3", 1],
  [".001e3", 1],
  ["-12e2", -1200],
  ["9007199254740991", 9007199254740991],
  ["-9007199254740991", -9007199254740991],
  ["0e999999", 0],
  ["+00012", 12],
  ["1.", 1],
])("converts exactly integral decimal input %s", (text, expected) => {
  expect(exactIntegerInput(String(text))).toBe(expected);
});

it.each([
  "0.999999999999999999999",
  "9007199254740991.1",
  "1e-1000",
  "1e1000",
  "9007199254740993",
  "1.25",
  "0x10",
  "NaN",
  "Infinity",
  "",
  "1e",
  "--1",
])("preserves inexact or incomplete input %s for correction", (text) => {
  expect(exactIntegerInput(text)).toBeUndefined();
});

it.each([
  "0.999999999999999999999",
  "9007199254740991.1",
  "1e-1000",
  "1e1000",
  "9007199254740993",
  "1.25",
])(
  "rejects original advanced JSON number %s before its rounded value can be used",
  (token) => {
    expect(() => parseParameterJson(`{"nested":[{"value":${token}}]}`)).toThrow(
      InexactParameterNumber,
    );
  },
);

it("preserves exact decimal strings and ignores escaped numeric-looking string content", () => {
  const value = {
    amount: "9007199254740991.1",
    label: 'quote " and slash \\ 1e-1000',
    count: 4,
  };
  expect(parseParameterJson(JSON.stringify(value))).toEqual(value);
  expect(parseParameterJson('{"count":1000e-3,"other":1.000}')).toEqual({
    count: 1,
    other: 1,
  });
  expect(() => parseParameterJson('{"count":01}')).toThrow(SyntaxError);
});
