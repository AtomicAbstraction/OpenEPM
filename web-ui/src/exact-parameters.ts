/** Parameter JSON numbers are exact safe integers; decimal values use strings. */
export class InexactParameterNumber extends Error {
  constructor() {
    super(
      "Numeric parameters must be exact safe integers. Declare exact decimal parameters as strings.",
    );
  }
}

/** Convert only when the written decimal value itself is an exact safe integer. */
export function exactIntegerInput(text: string): number | undefined {
  const match =
    /^([+-]?)(?:(\d+)(?:\.(\d*))?|\.(\d+))(?:[eE]([+-]?\d+))?$/.exec(
      text.trim(),
    );
  if (!match) return undefined;
  const fraction = match[3] ?? match[4] ?? "";
  let digits = ((match[2] ?? "") + fraction).replace(/^0+/, "");
  if (!digits) return 0;
  const exponent = Number(match[5] ?? "0");
  if (!Number.isSafeInteger(exponent)) return undefined;
  const scale = exponent - fraction.length;
  if (scale >= 0) {
    if (digits.length + scale > 16) return undefined;
    digits += "0".repeat(scale);
  } else {
    const remove = -scale;
    if (remove >= digits.length || /[^0]/.test(digits.slice(-remove)))
      return undefined;
    digits = digits.slice(0, -remove);
  }
  if (digits.length > 16) return undefined;
  const integer = BigInt((match[1] === "-" ? "-" : "") + digits);
  if (integer < -9007199254740991n || integer > 9007199254740991n)
    return undefined;
  return Number(integer);
}

/** Validate original numeric tokens before a parsed value can lose precision. */
export function parseParameterJson(text: string): unknown {
  const parsed: unknown = JSON.parse(text);
  const number = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
  let index = 0;
  while (index < text.length) {
    if (text[index] === '"') {
      index++;
      while (index < text.length && text[index] !== '"') {
        index += text[index] === "\\" ? 2 : 1;
      }
      index++;
    } else if (text[index] === "-" || /[0-9]/.test(text[index])) {
      number.lastIndex = index;
      const token = number.exec(text);
      if (!token || exactIntegerInput(token[0]) === undefined)
        throw new InexactParameterNumber();
      index = number.lastIndex;
    } else {
      index++;
    }
  }
  return parsed;
}
