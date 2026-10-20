export interface DocsVersion {
  version: string;
  label: string;
  basePath: string | null;
  isLatest: boolean;
  gitRef: string;
}

// The version shown in the docs header badge is sourced at build time from
// NEXT_PUBLIC_DOCS_VERSION, which the deploy-docs workflow derives from the
// git tag (`git describe --tags`) — the SAME source of truth the binary uses
// (Makefile: `VERSION ?= $(shell git describe --tags ...)`). A release tag is
// therefore the single place the version is set, so the docs badge can't drift
// to a stale value nobody remembered to bump. Falls back to "dev" for local
// builds (`npm run dev`, or `npm run build` with no env set).
const docsVersion = process.env.NEXT_PUBLIC_DOCS_VERSION?.trim() || "dev";

export const versions: DocsVersion[] = [
  {
    version: docsVersion,
    label: `v${docsVersion} (latest)`,
    basePath: null,
    isLatest: true,
    gitRef: "main",
  },
];

export const currentVersion = versions.find((v) => v.isLatest)!;
export const hasMultipleVersions = versions.length > 1;
