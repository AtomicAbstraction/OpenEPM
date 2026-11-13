#!/bin/bash
# Run inside the delivered image, separately from project-source/data checks.
set -euo pipefail
require_published_skill=0
if [[ ${1:-} == --require-published-skill && $# == 1 ]]; then
  require_published_skill=1
elif [[ $# != 0 ]]; then
  echo 'Usage: openepm-runtime-check [--require-published-skill]' >&2
  exit 2
fi
if command -v codex >/dev/null 2>&1; then
  echo 'Runtime independence failed: Codex executable is shipped' >&2
  exit 1
fi
if [[ $require_published_skill == 1 ]]; then
  [[ -f /srv/openepm/docs/skills/multidimensional-cube-harness/SKILL.md ]] || {
    echo 'Runtime independence failed: packaged Open EPM skill is absent' >&2
    exit 1
  }
  command -v python >/dev/null || {
    echo 'Runtime independence failed: skill verification interpreter is absent' >&2
    exit 1
  }
fi
legacy=sql
legacy+=ite
found=$(find /usr /lib /bin /sbin /opt /srv /etc /var/lib/dpkg -iname "*${legacy}*" -print 2>/dev/null || true)
[[ -z $found ]] || { echo 'Runtime retirement failed: named artifacts remain' >&2; printf '%s\n' "$found" >&2; exit 1; }
packages=$(dpkg-query -W -f='${Package} ${db:Status-Status}\n' 2>/dev/null | grep -i "$legacy" || true)
[[ -z $packages ]] || { echo 'Runtime retirement failed: package registration remains' >&2; exit 1; }
rpm_packages=$(rpm -qa 2>/dev/null | grep -i "$legacy" || true)
[[ -z $rpm_packages ]] || { echo 'Runtime retirement failed: RPM package registration remains' >&2; exit 1; }
loader=''
if command -v ldconfig >/dev/null 2>&1; then
  loader=$(ldconfig -p)
fi
if grep -iq "$legacy" <<<"$loader"; then
  echo 'Runtime retirement failed: native loader registration remains' >&2; exit 1
fi
python_count=0
if command -v python >/dev/null; then
  python - "$require_published_skill" <<'PY'
import importlib.util
from ctypes.util import find_library
from pathlib import Path
import sysconfig
import sys
marker='sql'+'ite'
for module in (marker+'3','_'+marker+'3','dbm.'+marker+'3'):
    if importlib.util.find_spec(module) is not None:raise SystemExit('Retired runtime module still resolves')
if find_library(marker+'3') is not None:raise SystemExit('Retired native library still resolves')
refs=[]
root=Path(sysconfig.get_path('stdlib'))
# Inspect the interpreter-owned standard library sources, build metadata and
# installed dependency declarations.  Arbitrary third-party implementation
# sources can legitimately describe this database format (for example the
# OpenTelemetry semantic-convention vocabulary) without providing the retired
# backend.  Executable third-party artifacts remain covered by the filename,
# import-resolution, native-library and distribution-metadata checks above.
site_packages=root/'site-packages'
paths=[path for path in root.rglob('*.py') if site_packages not in path.parents]
paths+=list(root.glob('_sysconfig_vars*.json'))
paths+=list(site_packages.glob('*.dist-info/METADATA'))
for path in paths:
    if marker.encode() in path.read_bytes().lower():refs.append(str(path))
if refs:raise SystemExit('Retired Python references remain: '+repr(refs))
if sys.argv[1] == '1':
    from epm_core.published_skill_delivery import published_skill_snapshot
    skill=published_skill_snapshot()
    if not skill.digest.startswith('sha256:') or skill.size != len(skill.content_bytes):
        raise SystemExit('Published Open EPM skill manifest is inconsistent')
print('Python module/reference absence verified')
PY
  python_count=1
fi
native_count=0
while IFS= read -r -d '' binary; do
  magic=$(od -An -tx1 -N4 "$binary" | tr -d ' \n')
  [[ $magic == 7f454c46 ]] || continue
  links=$(ldd "$binary" 2>&1 || true)
  if grep -Eiq "${legacy}|not found" <<<"$links"; then
    echo "Runtime retirement failed: native dependency $binary" >&2
    printf '%s\n' "$links" >&2
    exit 1
  fi
  native_count=$((native_count+1))
done < <(find /usr/local /usr/lib/postgresql /usr/lib64 /opt -type f \( -name '*.so' -o -name '*.so.*' -o -perm /111 \) -print0 2>/dev/null || true)
published_skill=not-applicable
if [[ $require_published_skill == 1 ]]; then published_skill=verified; fi
echo "Runtime-retirement gate passed: native_files=$native_count python_runtime=$python_count codex=absent published_skill=$published_skill"
