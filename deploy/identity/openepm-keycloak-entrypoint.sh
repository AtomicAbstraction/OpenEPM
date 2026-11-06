#!/bin/sh
set -eu

read_secret() {
    name=$1
    path=$2
    [ -f "$path" ] && [ ! -L "$path" ] || {
        printf 'openepm-keycloak: missing secret: %s\n' "$name" >&2
        exit 78
    }
    value=$(cat "$path")
    [ -n "$value" ] && [ "${#value}" -le 8192 ] || {
        printf 'openepm-keycloak: invalid secret: %s\n' "$name" >&2
        exit 78
    }
    case "$value" in *"
"*) printf 'openepm-keycloak: multiline secret rejected: %s\n' "$name" >&2; exit 78;; esac
    printf '%s' "$value"
}

require_secret_file() {
    name=$1
    path=$2
    [ -f "$path" ] && [ ! -L "$path" ] && [ -s "$path" ] || {
        printf 'openepm-keycloak: invalid file secret: %s\n' "$name" >&2
        exit 78
    }
}

case "${KC_HOSTNAME:-}" in https://*) ;; *)
    printf '%s\n' 'openepm-keycloak: KC_HOSTNAME must be an HTTPS URL' >&2; exit 78;;
esac
export KC_BOOTSTRAP_ADMIN_USERNAME="$(read_secret bootstrap-admin-username "${KC_BOOTSTRAP_ADMIN_USERNAME_FILE:?}")"
case "$KC_BOOTSTRAP_ADMIN_USERNAME" in
    ''|*[!A-Za-z0-9._-]*) printf '%s\n' 'openepm-keycloak: invalid bootstrap administrator name' >&2; exit 78;;
esac

export KC_DB_URL="$(read_secret database-url "${KC_DB_URL_FILE:?}")"
export KC_DB_USERNAME="$(read_secret database-username "${KC_DB_USERNAME_FILE:?}")"
export KC_DB_PASSWORD="$(read_secret database-password "${KC_DB_PASSWORD_FILE:?}")"
export KC_BOOTSTRAP_ADMIN_PASSWORD="$(read_secret bootstrap-admin-password "${KC_BOOTSTRAP_ADMIN_PASSWORD_FILE:?}")"
require_secret_file internal-tls-certificate "${KC_HTTPS_CERTIFICATE_FILE:?}"
require_secret_file internal-tls-private-key "${KC_HTTPS_CERTIFICATE_KEY_FILE:?}"

exec /opt/keycloak/bin/kc.sh start --optimized \
    --http-enabled=false \
    --https-port=8443 \
    --proxy-headers=xforwarded
