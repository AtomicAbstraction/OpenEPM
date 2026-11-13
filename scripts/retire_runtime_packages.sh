#!/bin/bash
# Build-stage only: remove the retired native backend and its unused consumers.
set -euo pipefail
[[ ${1:-} == app || ${1:-} == db ]] || { echo 'Expected image variant' >&2; exit 2; }
[[ $(id -u) == 0 && -f /etc/openepm-image-build ]] || { echo 'Image-build guard required' >&2; exit 2; }
legacy=sql
legacy+=ite
backend="lib${legacy}3-0"
if [[ $1 == app ]]; then
  targets=(util-linux)
  # Debian Trixie split lastlog into a package that is not present in the
  # pinned Bookworm operations-builder base.  Keep the removal closure exact
  # for both bases without asking apt to resolve a nonexistent package.
  dpkg-query -W -f='${db:Status-Status}\n' liblastlog2-2 2>/dev/null | grep -qx installed \
    && targets+=(liblastlog2-2)
  targets+=("$backend")
  expected=$(printf '%s\n' "${targets[@]}" | sort)
  options=(--allow-remove-essential)
else
  targets=("$backend")
  expected=$(printf '%s\n' gnupg gpg gpg-wks-client gpg-wks-server "$backend" | sort)
  options=()
fi
# The immutable base digest determines this exact removal closure. Fail closed
# if another runtime package would be removed instead of accepting a new plan.
actual=$(LC_ALL=C apt-get -s "${options[@]}" purge "${targets[@]}" | awk '/^Purg / {print $2}' | sort)
[[ $actual == "$expected" ]] || { echo 'Unexpected package retirement closure' >&2; printf '%s\n' "$actual" >&2; exit 1; }
DEBIAN_FRONTEND=noninteractive apt-get -y "${options[@]}" purge "${targets[@]}"
rm -f /var/lib/dpkg/status-old /var/lib/dpkg/available /var/lib/dpkg/available-old
# The vendor file contains a historical package-size comment, not a live setting.
sed -i "/${legacy}/Id" /etc/dpkg/dpkg.cfg.d/docker
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* /var/log/apt/*
rm -f /var/log/dpkg.log /var/log/alternatives.log
# Final runtime images are flattened appliances, not package-management hosts.
# Package notices are emitted into the release license bundle; manuals,
# compressed alternatives state and broken documentation links are not runtime
# inputs and cannot remain as opaque or dangling filesystem payloads.
rm -rf /usr/share/doc /usr/share/man /var/lib/dpkg/alternatives
find /etc/alternatives -xtype l -delete
