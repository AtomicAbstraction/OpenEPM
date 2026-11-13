"""Fail a release while legacy storage or the retired research product remains.

This checks executable/project data artifacts, including old tests and web
assets. Historical Markdown input records and migration notes are retained.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
MARKER = ("sql" + "ite").encode()
DATABASE_HEADER = MARKER[:3].upper() + MARKER[3:] + b' format 3\x00'
SOURCE_SUFFIXES = {'.py', '.js', '.mjs', '.jsx', '.ts', '.tsx', '.html',
                   '.css', '.json', '.sql', '.sh', '.plist', '.toml',
                   '.yaml', '.yml', '.lock'}
SKIP_DIRS = {
    '__pycache__', 'node_modules', '.git', '.cursor',
    '.mypy_cache', '.pytest_cache', '.ruff_cache',
}
RETIRED_RESEARCH_DIRS = (
    'ingestion', 'knowledge', 'research', 'data/ingestion-runs',
    'data/ingestion-sources',
)
RETIRED_RESEARCH_FILES = (
    'agent.mjs', 'server.mjs', 'export-catalogue.py',
    'content-ingestion-workflow.html',
    'web/ingestion.html', 'web/catalogue.html', 'web/report.html',
    'Senior_Finance_Executive_AI_Enterprise_Application_Catalogue_SPEC.md',
)
RETIRED_V1_FIXTURES = (
    'sample_financials',
    'examples/it_cost_planning_metadata_scan.json',
)


def findings(root: Path = ROOT) -> list[tuple[str, str]]:
    found = []
    for relative in (*RETIRED_RESEARCH_DIRS, *RETIRED_RESEARCH_FILES):
        path = root / relative
        if path.exists() or path.is_symlink():
            found.append((relative, 'retired research product path'))
    for relative in RETIRED_V1_FIXTURES:
        path = root / relative
        if path.exists() or path.is_symlink():
            found.append((relative, 'retired V1 fixture path'))
    data_dir = root / 'data'
    if data_dir.is_dir():
        for path in sorted(data_dir.glob('catalogue*')):
            found.append((str(path.relative_to(root)),
                          'retired research product data'))
    legacy_entrypoints = {
        'scripts/serve_openepm_mcp.sh': b'platform_program_mcp_http.py',
        'scripts/serve_local_5187.sh': b'server.mjs',
        'package.json': b'node' + b' server.mjs',
    }
    for relative, command in legacy_entrypoints.items():
        launcher = root / relative
        if launcher.is_file() and command in launcher.read_bytes():
            found.append((relative, 'still launches the V1 runtime'))
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(item for item in dirs if item not in SKIP_DIRS)
        for name in sorted(files):
            path = Path(directory, name)
            relative = str(path.relative_to(root))
            if MARKER in relative.lower().encode():
                found.append((relative, 'filename'))
                continue
            try:
                if path.is_symlink():
                    if not path.is_file():
                        continue
                    with path.open('rb') as stream:
                        if stream.read(len(DATABASE_HEADER)) == DATABASE_HEADER:
                            found.append((relative, 'linked database header'))
                    continue
                with path.open('rb') as stream:
                    header = stream.read(len(DATABASE_HEADER))
                    if header == DATABASE_HEADER:
                        found.append((relative, 'database header'))
                        continue
                    if path.suffix.lower() not in SOURCE_SUFFIXES:
                        continue
                    content = header + stream.read()
            except OSError as error:
                found.append((relative, f'unreadable: {error.strerror}'))
                continue
            if MARKER in content.lower():
                found.append((relative, 'content'))
    return found


def main() -> int:
    remaining = findings()
    if remaining:
        print(f'Storage-retirement gate failed: {len(remaining)} artifacts remain')
        for path, reason in remaining:
            print(f'{path}: {reason}')
        return 1
    print('Storage-retirement gate passed: no legacy database or research-product artifacts')
    return 0


if __name__ == '__main__':
    sys.exit(main())
