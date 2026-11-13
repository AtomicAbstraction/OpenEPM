export type WorkspaceArea =
  | "data"
  | "lists"
  | "rules"
  | "security"
  | "administration";

export type WorkspaceSection = {
  id: string;
  label: string;
  description: string;
  prefixes: string[];
};

export const workspaceSections: Record<WorkspaceArea, WorkspaceSection[]> = {
  data: [
    {
      id: "import",
      label: "Import",
      description:
        "Validate a data file, review its exact scope, then publish it.",
      prefixes: ["facts.transfer.import", "facts.source."],
    },
    {
      id: "export",
      label: "Export",
      description:
        "Create and download a governed snapshot of application data.",
      prefixes: ["facts.transfer.export"],
    },
    {
      id: "detail",
      label: "Supporting detail",
      description: "Inspect and maintain the detail lines behind a value.",
      prefixes: ["facts.line-detail."],
    },
    {
      id: "activity",
      label: "Recent activity",
      description: "Inspect recent imports, exports and detail changes.",
      prefixes: [],
    },
    {
      id: "reference",
      label: "Function reference",
      description: "Inspect the data functions available to your current role.",
      prefixes: ["facts.transfer.", "facts.source.", "facts.line-detail."],
    },
  ],
  rules: [
    {
      id: "python",
      label: "Python programs",
      description:
        "Write Python, validate the current source, test its effects and activate it.",
      prefixes: [
        "python.program.",
        "python.environment.",
        "python.build.",
        "python.workflow.",
      ],
    },
    {
      id: "rules",
      label: "Calculation rules",
      description: "Author, publish and run reusable rules.",
      prefixes: ["application.rule.", "facts.rule.", "rules.expression."],
    },
    {
      id: "calculations",
      label: "Calculated members",
      description:
        "Inspect published member calculations and their dependencies.",
      prefixes: ["calculated.member."],
    },
    {
      id: "sequences",
      label: "Sequences",
      description:
        "Inspect ordered calculation statements and run a published sequence.",
      prefixes: ["application.sequence.", "rules.numeric_sequence."],
    },
    {
      id: "schedules",
      label: "Schedules",
      description: "Inspect and maintain scheduled application work.",
      prefixes: ["application.schedule.", "schedule."],
    },
    {
      id: "authorities",
      label: "Execution authorities",
      description: "Control who can build, run or advance an approved program.",
      prefixes: ["execution.delegation."],
    },
    {
      id: "python-schedules",
      label: "Program schedules",
      description:
        "Maintain recurring program runs and inspect their occurrences.",
      prefixes: ["python.schedule."],
    },
    {
      id: "reference",
      label: "Function reference",
      description:
        "Inspect the calculation and execution functions available to your current role.",
      prefixes: [
        "application.rule.",
        "application.sequence.",
        "rules.numeric_sequence.",
        "application.schedule.",
        "schedule.",
        "calculated.member.",
        "python.",
        "execution.delegation.",
        "facts.expression",
        "facts.rule",
        "rules.expression",
        "application.program",
      ],
    },
  ],
  lists: [
    {
      id: "lists",
      label: "Member lists",
      description: "Save, publish and evaluate reusable dimension selections.",
      prefixes: ["metadata.member_list."],
    },
    {
      id: "reference",
      label: "Function reference",
      description:
        "Inspect the member-list functions available to your current role.",
      prefixes: ["metadata.member_list."],
    },
  ],
  security: [
    {
      id: "security",
      label: "Users & access",
      description:
        "Manage application grants, role permissions and dimensional access.",
      prefixes: ["security.", "application.dimension.access"],
    },
    {
      id: "policy",
      label: "Dimensional policy",
      description:
        "Inspect the active access policy and review an exact policy change.",
      prefixes: ["security.application.dimension-policy."],
    },
    {
      id: "audit",
      label: "Security audit",
      description: "Inspect security events and their committed receipts.",
      prefixes: [
        "security.application.audit.",
        "security.application.receipt.",
      ],
    },
    {
      id: "reference",
      label: "Function reference",
      description:
        "Inspect the security functions available to your current role.",
      prefixes: ["security.", "application.dimension.access"],
    },
  ],
  administration: [
    {
      id: "lifecycle",
      label: "Application state",
      description:
        "Inspect this application's identity, status and current revisions.",
      prefixes: [
        "application.lifecycle",
        "application.maintenance",
        "application.reset",
      ],
    },
    {
      id: "reference",
      label: "Function reference",
      description:
        "Inspect the administration functions available to your current role.",
      prefixes: [
        "application.lifecycle",
        "application.maintenance",
        "application.reset",
      ],
    },
  ],
};

export function workspaceSectionForArtifact(kind?: string) {
  return kind === "ApplicationRule"
    ? "rules"
    : kind === "CalculatedMember"
      ? "calculations"
      : kind === "ApplicationSequence"
        ? "sequences"
        : kind === "ApplicationSchedule"
          ? "schedules"
          : undefined;
}

export function resolveWorkspaceSection(
  area: WorkspaceArea,
  section?: string,
  artifactKind?: string,
): string {
  const candidate =
    section ||
    (area === "rules" ? workspaceSectionForArtifact(artifactKind) : undefined);
  return workspaceSections[area].some((item) => item.id === candidate)
    ? candidate!
    : workspaceSections[area][0].id;
}
