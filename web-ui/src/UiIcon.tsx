const paths: Record<string, string> = {
  home: "M3 10 12 3l9 7M5 9v12h5v-7h4v7h5V9",
  applications: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
  work: "M8 4H5v17h14V4h-3M8 2h8v5H8zM8 13l3 3 5-6",
  tasks: "M8 4H5v17h14V4h-3M8 2h8v5H8zM8 13l3 3 5-6",
  server: "M3 3h18v7H3zM3 14h18v7H3zM7 6h.01M7 17h.01M16 6h2M16 17h2",
  overview: "M3 3v18h18M7 16v-5M12 16V7M17 16v-8",
  grid: "M3 3h18v18H3zM3 9h18M9 3v18M3 15h18",
  data: "M7 3v14m-4-4 4 4 4-4M17 21V7m-4 4 4-4 4 4",
  metadata: "m12 3 10 5-10 5L2 8zM2 12l10 5 10-5M2 16l10 5 10-5",
  rules: "m8 6-6 6 6 6m8-12 6 6-6 6M14 3l-4 18",
  flows: "M3 3h6v6H3zM15 15h6v6h-6zM6 9v9h9M9 6h9v9",
  monitor: "M2 12h5l3-8 4 16 3-8h5",
  security: "m12 2 9 4v6c0 5-9 10-9 10S3 17 3 12V6zM8 12l3 3 5-6",
  administration: "M3 7h18M3 17h18M7 4v6M17 14v6",
  search: "M16 16l6 6M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0",
  print: "M7 8V3h10v5M7 17H3V8h18v9h-4M7 13h10v8H7zM17 11h.01",
  link: "m9 15 6-6M10 7l2-2a5 5 0 0 1 7 7l-2 2M14 17l-2 2a5 5 0 0 1-7-7l2-2",
  notifications: "M6 8a6 6 0 0 1 12 0v5l3 4H3l3-4zM9 21h6",
  help: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20M9 8a3 3 0 0 1 6 0c0 2-3 2-3 5M12 17h.01",
  arrow: "M4 12h16m-6-6 6 6-6 6",
};

export function UiIcon({ name }: { name: string }) {
  return (
    <svg
      className="ui-icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={paths[name] || paths.applications} />
    </svg>
  );
}
