#!/bin/zsh
set -euo pipefail

SCRIPT_DIR=${0:A:h}
PROJECT_DIR=${SCRIPT_DIR:h}
RELEASES=${PROJECT_DIR}/.epm-runtime/public-landing/releases
CURRENT=${PROJECT_DIR}/.epm-runtime/public-landing/current
SITE_ROOT=${PROJECT_DIR}/public-landing
if [[ -e ${CURRENT} || -L ${CURRENT} ]]; then
  SITE_ROOT=${CURRENT:A}
  if [[ ${SITE_ROOT:h} != ${RELEASES:A} || ! ${SITE_ROOT:t} =~ '^(site|recovery)-[0-9a-f]{64}$' ]]; then
    print -u2 'Open EPM landing: invalid current release'
    exit 78
  fi
fi
SERVER=${SITE_ROOT}/server.mjs
NODE_BIN=${OPEN_EPM_NODE:-}

if [[ -z ${NODE_BIN} ]]; then
  candidates=("${NVM_DIR:-${HOME}/.nvm}"/versions/node/*/bin/node(N))
  (( ${#candidates} > 0 )) || { print -u2 'Open EPM landing: Node executable not found'; exit 78; }
  NODE_BIN=${candidates[-1]}
fi
[[ -x ${NODE_BIN} && -f ${SERVER} ]] || { print -u2 'Open EPM landing: runtime files unavailable'; exit 78; }

export OPEN_EPM_LANDING_HOST=127.0.0.1
export OPEN_EPM_LANDING_PORT=5186
export OPEN_EPM_LANDING_ROOT=${SITE_ROOT}
exec ${NODE_BIN} ${SERVER}
