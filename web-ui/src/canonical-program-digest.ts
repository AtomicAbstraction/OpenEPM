// Match postgres_jobs._canonical_digest on typed program values.
function compareKeys(left: string, right: string): number {
  const a = Array.from(left, (c) => c.codePointAt(0)!);
  const b = Array.from(right, (c) => c.codePointAt(0)!);
  for (let i = 0; i < Math.min(a.length, b.length); i++)
    if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

export function canonicalProgramJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value))
    return JSON.stringify(value);
  if (Array.isArray(value))
    return `[${value.map(canonicalProgramJson).join(",")}]`;
  if (typeof value === "object") {
    const fields = value as Record<string, unknown>;
    return `{${Object.keys(fields)
      .sort(compareKeys)
      .map(
        (key) => `${JSON.stringify(key)}:${canonicalProgramJson(fields[key])}`,
      )
      .join(",")}}`;
  }
  throw new Error(
    "The typed program contains an inexact or unsupported value.",
  );
}

export async function canonicalProgramDigest(
  value: unknown,
  asciiOnly = false,
): Promise<string> {
  let json = canonicalProgramJson(value);
  if (asciiOnly)
    json = json.replace(
      /[\u007f-\uffff]/g,
      (character) =>
        "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"),
    );
  const result = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(json),
  );
  return Array.from(new Uint8Array(result), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
