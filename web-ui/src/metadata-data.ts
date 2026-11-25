import type { ApplicationSummary } from "./types";
import { collectAllContinuations } from "./continuation";

export type MetadataDimension = {
  dimension_id: string;
  name: string;
  model_role: string;
  status: string;
  short_description?: string;
  detailed_description?: string;
};

export type MetadataMember = {
  member_id: string;
  name: string;
  status: string;
  short_description?: string;
  detailed_description?: string;
  numeric_value_kind?: "amount" | "ratio" | null;
  custom_values?: Record<string, unknown>;
};

type AttributeDefinitionPage<Row> = {
  rows: Row[];
  nextAfterAttributeId: string | null;
  nextPageToken?: string | null;
  metadataRevision: number;
  hasMore?: boolean;
};

export function attributeDefinitionContinuation(
  afterAttributeId: string | null,
  previous?: { metadataRevision: number; nextPageToken?: string | null },
) {
  return afterAttributeId
    ? {
        afterAttributeId,
        ...(previous?.nextPageToken
          ? {
              expectedMetadataRevision: previous.metadataRevision,
              expectedPageToken: previous.nextPageToken,
            }
          : {}),
      }
    : {};
}

export function collectCapabilityAttributeDefinitions<
  Row extends { attribute_id: string },
>(
  readPage: (
    continuation: ReturnType<typeof attributeDefinitionContinuation>,
  ) => Promise<AttributeDefinitionPage<Row>>,
  {
    expectedMetadataRevision,
    maximumRows,
  }: {
    expectedMetadataRevision?: number;
    maximumRows?: number;
  } = {},
) {
  let previous: AttributeDefinitionPage<Row> | undefined;
  let count = 0;
  return collectAllContinuations<AttributeDefinitionPage<Row>, Row>({
    label: "Attribute definitions",
    readPage: async (after) => {
      const page = await readPage(
        attributeDefinitionContinuation(after, previous),
      );
      previous = page;
      return page;
    },
    rows: (page) => {
      if (
        page.hasMore !== undefined &&
        page.hasMore !== (page.nextAfterAttributeId !== null)
      )
        throw new Error("Invalid attribute continuation.");
      if (maximumRows !== undefined && Array.isArray(page.rows)) {
        count += page.rows.length;
        if (count > maximumRows)
          throw new Error(
            `The attribute catalogue exceeds its governed ${maximumRows}-column bound.`,
          );
      }
      return page.rows;
    },
    nextCursor: (page) => page.nextAfterAttributeId,
    rowIdentity: (row) => row.attribute_id,
    consistencyIdentity: (page) => {
      if (
        expectedMetadataRevision !== undefined &&
        page.metadataRevision !== expectedMetadataRevision
      )
        throw new Error(
          "Metadata changed while reading attribute definitions.",
        );
      return page.metadataRevision;
    },
  });
}

export function activeFactDimensions(dimensions: MetadataDimension[]) {
  return dimensions.filter(
    (dimension) =>
      dimension.status === "Active" && dimension.model_role !== "Currency",
  );
}

export function dimensionListArguments(
  afterDimensionId?: string | null,
  expectedMetadataRevision?: number,
  expectedPageToken?: string | null,
): {
  limit: number;
  afterDimensionId?: string;
  expectedMetadataRevision?: number;
  expectedPageToken?: string;
} {
  return afterDimensionId
    ? {
        limit: 100,
        afterDimensionId,
        expectedMetadataRevision,
        ...(expectedPageToken ? { expectedPageToken } : {}),
      }
    : { limit: 100 };
}

export function memberListArguments(
  dimension: string,
  afterMemberId?: string | null,
  expectedMetadataRevision?: number,
  expectedPageToken?: string | null,
) {
  return afterMemberId
    ? {
        dimension,
        limit: 100,
        afterMemberId,
        expectedMetadataRevision,
        ...(expectedPageToken ? { expectedPageToken } : {}),
      }
    : {
        dimension,
        limit: 100,
        ...(expectedMetadataRevision === undefined
          ? {}
          : { expectedMetadataRevision }),
      };
}

type DimensionPage = {
  rows: MetadataDimension[];
  nextAfterDimensionId: string | null;
  metadataRevision: number;
  nextPageToken?: string | null;
};

type MemberPage = {
  rows: MetadataMember[];
  nextAfterMemberId: string | null;
  metadataRevision: number;
  nextPageToken?: string | null;
};

export function collectCapabilityDimensions(
  readPage: (
    arguments_: ReturnType<typeof dimensionListArguments>,
  ) => Promise<DimensionPage>,
) {
  let revision: number | undefined;
  let token: string | null | undefined;
  return collectAllContinuations<DimensionPage, MetadataDimension>({
    label: "Metadata dimensions",
    readPage: async (cursor) => {
      const page = await readPage(
        dimensionListArguments(cursor, revision, token),
      );
      revision = page.metadataRevision;
      token = page.nextPageToken;
      return page;
    },
    rows: (page) => page.rows,
    nextCursor: (page) => page.nextAfterDimensionId,
    rowIdentity: (row) => row.dimension_id,
    consistencyIdentity: (page) => page.metadataRevision,
  });
}

export function collectCapabilityMembers(
  dimension: string,
  readPage: (
    arguments_: ReturnType<typeof memberListArguments>,
  ) => Promise<MemberPage>,
  expectedMetadataRevision?: number,
) {
  let revision: number | undefined = expectedMetadataRevision;
  let token: string | null | undefined;
  return collectAllContinuations<MemberPage, MetadataMember>({
    label: "Metadata members",
    readPage: async (cursor) => {
      const page = await readPage(
        memberListArguments(dimension, cursor, revision, token),
      );
      revision = page.metadataRevision;
      token = page.nextPageToken;
      return page;
    },
    rows: (page) => page.rows,
    nextCursor: (page) => page.nextAfterMemberId,
    rowIdentity: (row) => row.member_id,
    consistencyIdentity: (page) => {
      if (
        expectedMetadataRevision !== undefined &&
        page.metadataRevision !== expectedMetadataRevision
      )
        throw new Error(
          "Metadata changed while reading members. Refresh the model before editing.",
        );
      return page.metadataRevision;
    },
  });
}

export function exactMemberTags(value: string, label: string) {
  const tags = value
    .split(";")
    .map((tag) => tag.trim())
    .filter(Boolean);
  if (tags.length > 100) throw new Error(`${label} supports at most 100 tags.`);
  if (tags.length !== new Set(tags).size)
    throw new Error(`${label} contains a duplicate tag.`);
  if (tags.some((tag) => tag.length > 20 || tag.includes(";")))
    throw new Error(`${label} tags must be 1-20 characters.`);
  return tags;
}

export function memberSecurityMutationBody(
  app: ApplicationSummary,
  dimensionId: string,
  memberId: string,
  readTags: string[],
  writeTags: string[],
  expectedMetadataRevision: number,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: "metadata.member.security-tags.set",
      arguments: {
        dimensionId,
        memberId,
        readTags,
        writeTags,
        expectedMetadataRevision,
      },
    },
  };
}

export function memberSecurityStringMutationBody(
  app: ApplicationSummary,
  dimensionId: string,
  memberId: string,
  securityString: string,
  expectedMetadataRevision: number,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: "metadata.member.security-string.set",
      arguments: {
        dimensionId,
        memberId,
        securityString,
        expectedMetadataRevision,
      },
    },
  };
}
