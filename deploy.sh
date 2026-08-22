#!/usr/bin/env bash
# Reusable PostgreSQL-first deployment for a BDS Anti-DPI 3x-UI node.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${BDS_CONFIG_FILE:-${SCRIPT_DIR}/node.env}"
SECRETS_FILE="${BDS_SECRETS_FILE:-/etc/bds-dpi-bypass/node-secrets.env}"

log() {
    printf '[bds-dpi] %s\n' "$*"
}

die() {
    printf '[bds-dpi] ERROR: %s\n' "$*" >&2
    exit 1
}

require_root() {
    [[ ${EUID} -eq 0 ]] || die "Run this installer as root."
}

load_config() {
    [[ -r "${CONFIG_FILE}" ]] || die "Missing config file: ${CONFIG_FILE}. Copy node.env.example and edit it first."
    # shellcheck disable=SC1090
    source "${CONFIG_FILE}"

    : "${PANEL_DOMAIN:?PANEL_DOMAIN is required}"
    : "${SUB_DOMAIN:?SUB_DOMAIN is required}"
    : "${CDN_DOMAIN:?CDN_DOMAIN is required}"
    : "${DIRECT_DOMAIN:?DIRECT_DOMAIN is required}"

    SERVER_LABEL="${SERVER_LABEL:-SG1}"
    XUI_VERSION="${XUI_VERSION:-v3.6.0}"
    XUI_INSTALL_SHA256="${XUI_INSTALL_SHA256:-7bb41e811f2107a3182da9090f24893d3612b5b6310194a7dd1f9965ff29e0c8}"
    XUI_PANEL_PORT="${XUI_PANEL_PORT:-2053}"
    XUI_SUB_PORT="${XUI_SUB_PORT:-2096}"
    XUI_WEB_BASE_PATH="${XUI_WEB_BASE_PATH:-panel}"
    XUI_SUB_PATH="${XUI_SUB_PATH:-sub}"
    SUB_PROFILE_FILE="${SUB_PROFILE_FILE:-/etc/bds-dpi-bypass/subscription-profiles.json}"
    TLS_CERT_FILE="${TLS_CERT_FILE:-/etc/nginx/ssl/bds-node/cert.pem}"
    TLS_KEY_FILE="${TLS_KEY_FILE:-/etc/nginx/ssl/bds-node/key.pem}"
    REALITY_DEST="${REALITY_DEST:-www.google.com:443}"
    REALITY_SERVER_NAME="${REALITY_SERVER_NAME:-www.google.com}"
    ENABLE_BBR="${ENABLE_BBR:-true}"
    ENABLE_UFW="${ENABLE_UFW:-false}"
    DEPLOYMENT_PROFILE="${DEPLOYMENT_PROFILE:-full}"

    export SERVER_LABEL PANEL_DOMAIN SUB_DOMAIN CDN_DOMAIN DIRECT_DOMAIN
    export XUI_PANEL_PORT XUI_SUB_PORT XUI_WEB_BASE_PATH XUI_SUB_PATH
    export SUB_PROFILE_FILE
    export TLS_CERT_FILE TLS_KEY_FILE REALITY_DEST REALITY_SERVER_NAME
    export DEPLOYMENT_PROFILE
}

validate_config() {
    local domain
    [[ "${SERVER_LABEL}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$ ]] \
        || die "SERVER_LABEL must be 1-32 letters, numbers, underscores, or hyphens."
    for domain in "${PANEL_DOMAIN}" "${SUB_DOMAIN}" "${CDN_DOMAIN}" "${DIRECT_DOMAIN}"; do
        [[ "${domain}" =~ ^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$ ]] \
            || die "Invalid domain: ${domain}"
    done
    [[ "${XUI_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "XUI_VERSION must be a stable vX.Y.Z tag."
    [[ "${XUI_INSTALL_SHA256}" =~ ^[a-fA-F0-9]{64}$ ]] || die "XUI_INSTALL_SHA256 must be a SHA-256 digest."
    [[ "${XUI_PANEL_PORT}" =~ ^[0-9]+$ ]] && (( XUI_PANEL_PORT > 0 && XUI_PANEL_PORT < 65536 )) \
        || die "Invalid XUI_PANEL_PORT."
    [[ "${XUI_SUB_PORT}" =~ ^[0-9]+$ ]] && (( XUI_SUB_PORT > 0 && XUI_SUB_PORT < 65536 )) \
        || die "Invalid XUI_SUB_PORT."
    [[ "${XUI_PANEL_PORT}" != "${XUI_SUB_PORT}" ]] || die "Panel and subscription ports must differ."
    [[ "${XUI_WEB_BASE_PATH}" =~ ^[A-Za-z0-9_-]{4,64}$ ]] || die "XUI_WEB_BASE_PATH must be 4-64 safe characters."
    [[ "${XUI_SUB_PATH}" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || die "XUI_SUB_PATH must be 1-64 safe characters."
    [[ "${SUB_PROFILE_FILE}" == /* ]] || die "SUB_PROFILE_FILE must be an absolute path."
    [[ "${REALITY_DEST}" =~ ^[^[:space:]:]+:[0-9]+$ ]] || die "REALITY_DEST must look like host:port."
    [[ "${DEPLOYMENT_PROFILE}" == "full" || "${DEPLOYMENT_PROFILE}" == "cdn_vless_backup" ]] \
        || die "DEPLOYMENT_PROFILE must be full or cdn_vless_backup."
}

preflight() {
    [[ -r /etc/os-release ]] || die "Cannot identify the operating system."
    # shellcheck disable=SC1091
    source /etc/os-release
    case "${ID}" in
        ubuntu|debian) ;;
        *) die "Supported operating systems: Ubuntu and Debian." ;;
    esac
}

validate_tls_assets() {
    [[ -s "${TLS_CERT_FILE}" ]] || die "TLS certificate not found: ${TLS_CERT_FILE}"
    [[ -s "${TLS_KEY_FILE}" ]] || die "TLS private key not found: ${TLS_KEY_FILE}"
    openssl x509 -in "${TLS_CERT_FILE}" -noout >/dev/null 2>&1 || die "TLS certificate is invalid."
    openssl pkey -in "${TLS_KEY_FILE}" -pubout >/dev/null 2>&1 || die "TLS private key is invalid."
    [[ "$(openssl x509 -in "${TLS_CERT_FILE}" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" == \
       "$(openssl pkey -in "${TLS_KEY_FILE}" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" ]] \
        || die "TLS certificate and private key do not match."
}

backup_state() {
    local backup_dir timestamp path
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    backup_dir="/var/backups/bds-dpi-bypass/${timestamp}"
    install -d -m 700 "${backup_dir}"

    tar --xattrs --acls -C / -cf "${backup_dir}/filesystem.tar" --files-from /dev/null
    for path in /etc/nginx /etc/x-ui /etc/default/x-ui /etc/systemd/system/x-ui.service /etc/bds-dpi-bypass /usr/local/sbin/bds-dpi-show-subscriptions; do
        [[ -e "${path}" ]] && tar --xattrs --acls -C / -rf "${backup_dir}/filesystem.tar" "${path#/}"
    done
    gzip -f "${backup_dir}/filesystem.tar"
    gzip -t "${backup_dir}/filesystem.tar.gz"
    tar -tzf "${backup_dir}/filesystem.tar.gz" >/dev/null

    if systemctl is-active --quiet postgresql; then
        command -v pg_dump >/dev/null 2>&1 || die "PostgreSQL is active but pg_dump is unavailable."
        command -v pg_restore >/dev/null 2>&1 || die "PostgreSQL is active but pg_restore is unavailable."
        sudo -u postgres pg_dump -Fc xui > "${backup_dir}/xui-postgres.dump"
        test -s "${backup_dir}/xui-postgres.dump" || die "PostgreSQL backup is empty."
        pg_restore -l "${backup_dir}/xui-postgres.dump" > "${backup_dir}/xui-postgres.contents"
        test -s "${backup_dir}/xui-postgres.contents" || die "PostgreSQL backup catalog is empty."
    fi
    sha256sum "${backup_dir}"/* > "${backup_dir}/SHA256SUMS"
    (cd "${backup_dir}" && sha256sum -c SHA256SUMS)
    printf '%s\n' "${backup_dir}" > /var/lib/bds-dpi-bypass-last-backup
    log "Backup verified: ${backup_dir}"
}

ensure_secret_file() {
    local previous_umask
    install -d -m 700 "$(dirname "${SECRETS_FILE}")"
    previous_umask="$(umask)"
    umask 077
    touch "${SECRETS_FILE}"
    chmod 600 "${SECRETS_FILE}"
    umask "${previous_umask}"

    # shellcheck disable=SC1090
    source "${SECRETS_FILE}"
    if [[ -z "${XUI_USERNAME:-}" || -z "${XUI_PASSWORD:-}" ]]; then
        XUI_USERNAME="bdsadmin_$(openssl rand -hex 4)"
        XUI_PASSWORD="$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9_-')"
        [[ ${#XUI_PASSWORD} -ge 24 ]] || XUI_PASSWORD="$(openssl rand -hex 24)"
        {
            printf 'XUI_USERNAME=%q\n' "${XUI_USERNAME}"
            printf 'XUI_PASSWORD=%q\n' "${XUI_PASSWORD}"
        } > "${SECRETS_FILE}"
        chmod 600 "${SECRETS_FILE}"
    fi
    export XUI_USERNAME XUI_PASSWORD
}

install_base_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ca-certificates curl nginx openssl python3 python3-cryptography postgresql-client sudo tar gzip
}

ensure_postgres_backend() {
    local env_file pg_password pg_user pg_dsn
    env_file="/etc/default/x-ui"
    if [[ -r "${env_file}" ]] && grep -q '^XUI_DB_TYPE=postgres$' "${env_file}"; then
        log "3x-UI PostgreSQL backend is already configured."
        return
    fi

    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y postgresql
    systemctl enable --now postgresql
    until sudo -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; do sleep 1; done

    pg_user="xui_$(openssl rand -hex 4)"
    pg_password="$(openssl rand -hex 32)"
    pg_dsn="postgres://${pg_user}:${pg_password}@127.0.0.1:5432/xui?sslmode=disable"

    sudo -u postgres psql -v ON_ERROR_STOP=1 -tAc \
        "CREATE ROLE \"${pg_user}\" LOGIN PASSWORD '${pg_password}'"
    if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='xui'" | grep -qx 1; then
        sudo -u postgres createdb -O "${pg_user}" xui
    else
        sudo -u postgres psql -v ON_ERROR_STOP=1 -c "ALTER DATABASE xui OWNER TO \"${pg_user}\";"
    fi

    systemctl stop x-ui 2>/dev/null || true
    /usr/local/x-ui/x-ui migrate-db --dsn "${pg_dsn}"

    install -d -m 755 /etc/default
    umask 077
    {
        printf 'XUI_DB_TYPE=postgres\n'
        printf 'XUI_DB_DSN=%q\n' "${pg_dsn}"
    } > "${env_file}"
    chmod 600 "${env_file}"
    umask 022
    systemctl daemon-reload
    log "3x-UI database migrated to PostgreSQL."
}

configure_panel_runtime() {
    local panel_username panel_password
    [[ -r /etc/default/x-ui ]] || die "Missing 3x-UI database environment file."
    panel_username="${XUI_USERNAME}"
    panel_password="${XUI_PASSWORD}"
    set -a
    # shellcheck disable=SC1091
    source /etc/default/x-ui
    set +a
    # The database environment file may contain legacy panel credentials. Keep
    # the root-only credential file as the single source of truth instead.
    XUI_USERNAME="${panel_username}"
    XUI_PASSWORD="${panel_password}"
    export XUI_USERNAME XUI_PASSWORD
    /usr/local/x-ui/x-ui setting \
        -username "${panel_username}" \
        -password "${panel_password}" \
        -port "${XUI_PANEL_PORT}" \
        -webBasePath "/"
    systemctl restart x-ui
    for _ in $(seq 1 30); do
        curl --silent --max-time 2 \
            "http://127.0.0.1:${XUI_PANEL_PORT}/login" >/dev/null 2>&1 && return
        sleep 1
    done
    die "3x-UI did not become ready after panel configuration."
}

install_3xui() {
    local current_version install_script actual_sha
    current_version=""
    if [[ -x /usr/local/x-ui/x-ui ]]; then
        current_version="$(/usr/local/x-ui/x-ui version 2>/dev/null | grep -Eo 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    fi
    if [[ -x /usr/local/x-ui/x-ui ]] && systemctl list-unit-files x-ui.service >/dev/null 2>&1; then
        if [[ -z "${current_version}" || "${current_version}" == "${XUI_VERSION}" ]]; then
            log "Existing 3x-UI installation detected; reusing it."
            return
        fi
        die "Installed 3x-UI version ${current_version} differs from pinned ${XUI_VERSION}; upgrade is not automatic."
    fi

    install_script="$(mktemp)"
    curl --fail --show-error --location \
        "https://raw.githubusercontent.com/MHSanaei/3x-ui/${XUI_VERSION}/install.sh" \
        --output "${install_script}"
    actual_sha="$(sha256sum "${install_script}" | awk '{print $1}')"
    [[ "${actual_sha}" == "${XUI_INSTALL_SHA256,,}" ]] || {
        rm -f "${install_script}"
        die "Pinned 3x-UI installer checksum mismatch."
    }

    XUI_NONINTERACTIVE=1 \
    XUI_SSL_MODE=none \
    XUI_DB_TYPE=postgres \
    XUI_PANEL_PORT="${XUI_PANEL_PORT}" \
    XUI_WEB_BASE_PATH="/" \
    XUI_USERNAME="${XUI_USERNAME}" \
    XUI_PASSWORD="${XUI_PASSWORD}" \
    bash "${install_script}" "${XUI_VERSION}"
    rm -f "${install_script}"
}

configure_3xui() {
    python3 "${SCRIPT_DIR}/scripts/04_configure_3xui_db.py" \
        --panel-url "http://127.0.0.1:${XUI_PANEL_PORT}" \
        --server-label "${SERVER_LABEL}" \
        --sub-domain "${SUB_DOMAIN}" \
        --sub-port "${XUI_SUB_PORT}" \
        --sub-path "${XUI_SUB_PATH}" \
        --cdn-domain "${CDN_DOMAIN}" \
        --direct-domain "${DIRECT_DOMAIN}" \
        --reality-dest "${REALITY_DEST}" \
        --reality-server-name "${REALITY_SERVER_NAME}" \
        --deployment-profile "${DEPLOYMENT_PROFILE}" \
        --profiles-file "${SUB_PROFILE_FILE}"

    if [[ "${DEPLOYMENT_PROFILE}" == "full" ]]; then
        python3 "${SCRIPT_DIR}/scripts/03_setup_warp.py" \
            --panel-url "http://127.0.0.1:${XUI_PANEL_PORT}"
    fi
}

install_operator_tools() {
    install -m 755 "${SCRIPT_DIR}/scripts/05_show_subscriptions.py" /usr/local/sbin/bds-dpi-show-subscriptions
    install -m 755 "${SCRIPT_DIR}/scripts/03_setup_warp.py" /usr/local/sbin/bds-dpi-verify-warp
}

configure_network() {
    if [[ "${ENABLE_BBR}" == "true" ]]; then
        bash "${SCRIPT_DIR}/scripts/01_setup_bbr.sh"
    fi
    bash "${SCRIPT_DIR}/scripts/02_setup_nginx.sh"

    if [[ "${ENABLE_UFW}" == "true" ]]; then
        command -v ufw >/dev/null 2>&1 || apt-get install -y ufw
        ufw allow OpenSSH
        ufw allow 80/tcp
        ufw allow 443/tcp
        if [[ "${DEPLOYMENT_PROFILE}" == "full" ]]; then
            ufw allow 10005/tcp
            ufw allow 10005/udp
            ufw allow 8443/tcp
        fi
        ufw --force enable
    fi
}

verify() {
    systemctl is-active --quiet postgresql || die "PostgreSQL is not active."
    systemctl is-active --quiet x-ui || die "3x-UI is not active."
    systemctl is-active --quiet nginx || die "Nginx is not active."
    grep -q '^XUI_DB_TYPE=postgres$' /etc/default/x-ui || die "3x-UI is not configured for PostgreSQL."
    sudo -u postgres psql -d xui -tAc 'SELECT 1' | grep -qx '1' || die "PostgreSQL xui database check failed."
    curl --fail --silent --show-error --max-time 10 \
        "http://127.0.0.1:${XUI_PANEL_PORT}/" >/dev/null
    curl --fail --silent --show-error --max-time 10 \
        --resolve "${CDN_DOMAIN}:443:127.0.0.1" \
        "https://${CDN_DOMAIN}/healthz" --insecure | grep -qx 'OK'
    ss -lnt | grep -Eq ":10001[[:space:]]" || die "VLESS CDN port 10001 is not listening."
    if [[ "${DEPLOYMENT_PROFILE}" == "full" ]]; then
        ss -lnt | grep -Eq ":10005[[:space:]]" || die "Direct Shadowsocks port 10005 is not listening."
        ss -lnt | grep -Eq ":8443[[:space:]]" || die "Reality port 8443 is not listening."
    fi
    python3 "${SCRIPT_DIR}/scripts/05_show_subscriptions.py" \
        --profiles-file "${SUB_PROFILE_FILE}" \
        --check-url-base "http://127.0.0.1:${XUI_SUB_PORT}/${XUI_SUB_PATH}" \
        --host-header "${SUB_DOMAIN}" \
        --expected-profile "${DEPLOYMENT_PROFILE}"
    if [[ "${DEPLOYMENT_PROFILE}" == "full" ]]; then
        python3 "${SCRIPT_DIR}/scripts/03_setup_warp.py" \
            --panel-url "http://127.0.0.1:${XUI_PANEL_PORT}" \
            --verify-only
    fi
    log "All local smoke tests passed."
}

main() {
    require_root
    load_config
    validate_config
    preflight
    backup_state
    install_base_packages
    validate_tls_assets
    ensure_secret_file
    install_3xui
    ensure_postgres_backend
    configure_panel_runtime
    configure_3xui
    configure_network
    install_operator_tools
    verify

    printf '\nDeployment complete.\n'
    printf 'Panel: https://%s/%s/\n' "${PANEL_DOMAIN}" "${XUI_WEB_BASE_PATH}"
    printf 'Subscription base: https://%s/%s/\n' "${SUB_DOMAIN}" "${XUI_SUB_PATH}"
    printf 'Subscription profile: %s (root-only)\n' "${SUB_PROFILE_FILE}"
    printf 'Show subscription link: sudo bds-dpi-show-subscriptions\n'
    printf 'Credentials: %s (root-only)\n' "${SECRETS_FILE}"
    printf 'Latest backup: %s\n' "$(cat /var/lib/bds-dpi-bypass-last-backup)"
}

main "$@"
