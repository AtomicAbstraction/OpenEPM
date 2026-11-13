import type { Plugin } from "vite";
export function browserLicenseNotices(): Plugin;
export function browserLicenseEvidence(root: string): {
  text: string;
  evidence: Record<string, unknown>;
};
