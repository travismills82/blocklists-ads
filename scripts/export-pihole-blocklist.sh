#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_FILE="${1:-${REPO_ROOT}/ads.txt}"
DB_PATH="${PIHOLE_GRAVITY_DB:-}"
CONTAINER="${PIHOLE_CONTAINER:-${PIHOLE_DOCKER_CONTAINER:-}}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

RAW_GRAVITY="${TMP_DIR}/gravity_raw.txt"
RAW_DENY="${TMP_DIR}/domainlist_deny_raw.txt"
RAW_ALLOW="${TMP_DIR}/domainlist_allow_raw.txt"
NORM_GRAVITY="${TMP_DIR}/gravity_norm.txt"
NORM_DENY="${TMP_DIR}/domainlist_deny_norm.txt"
NORM_ALLOW="${TMP_DIR}/domainlist_allow_norm.txt"
INVALID_ENTRIES="${TMP_DIR}/malformed.txt"
DENY_UNIQ="${TMP_DIR}/domainlist_deny_uniq.txt"
ALLOW_UNIQ="${TMP_DIR}/domainlist_allow_uniq.txt"
GRAVITY_UNIQ="${TMP_DIR}/gravity_uniq.txt"
COMBINED="${TMP_DIR}/combined_uniq.txt"
FINAL_SORTED="${TMP_DIR}/final_sorted.txt"
OUTPUT_TMP="${TMP_DIR}/ads.txt.tmp"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

run_sql() {
  local query="$1"
  if [[ -n "${SQL_BACKEND:-}" && "${SQL_BACKEND}" == "ssh" ]]; then
    ssh "${PIHOLE_SSH_TARGET}" pihole-FTL sqlite3 "${DB_PATH}" "${query}"
  elif [[ -n "${SQL_BACKEND:-}" && "${SQL_BACKEND}" == "docker" ]]; then
    docker exec -i "${CONTAINER}" pihole-FTL sqlite3 "${DB_PATH}" "${query}"
  else
    pihole-FTL sqlite3 "${DB_PATH}" "${query}"
  fi
}

sqlite_has_table() {
  local table="$1"
  run_sql "SELECT 1 FROM sqlite_master WHERE type='table' AND name='${table}';" \
    | tr -d '\r'
}

sqlite_has_column() {
  local table="$1"
  local column="$2"
  run_sql "PRAGMA table_info(${table});" \
    | awk -F'|' -v column="${column}" '$2==column {found=1} END {exit found?0:1}'
}

normalize_domains() {
  local input_file="$1"
  local output_file="$2"

  awk '
    function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
    function is_ipv4(s) { return (s ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) }
    function valid_domain(s,   i, n, parts, part, valid, len_part, label_count) {
      if (s == "" || s ~ /[()|^$*+?\[\]{}]/) return 0
      if (s ~ /[[:space:]]/) return 0
      if (s ~ /\.\./ || s ~ /^\./ || s ~ /\.$/ || s ~ /[ ]/) return 0
      if (s == "localhost") return 1
      if (s !~ /^[A-Za-z0-9_.-]+$/) return 0
      if (is_ipv4(s)) return 0
      n = split(s, parts, ".")
      if (n < 2) return 0
      for (i = 1; i <= n; i++) {
        part = parts[i]
        if (part == "" || length(part) > 63) return 0
        if (part !~ /^[A-Za-z0-9_-]+$/) return 0
        if (part ~ /^[-_]/ || part ~ /[-_]$/) return 0
      }
      return (n >= 2)
    }
  {
    line = trim($0)
    if (line == "" || substr(line, 1, 1) == "#") next

    sub(/[[:space:]]*#.*/, "", line)
    line = trim(line)
    if (line == "") next

    n = split(line, fields, /[[:space:]]+/)
    if (n == 0) next

    domain = fields[1]
    if (is_ipv4(domain)) {
      if (n < 2) next
      domain = fields[2]
    } else if (domain == "0.0.0.0" || domain == "127.0.0.1") {
      if (n < 2) next
      domain = fields[2]
    }

    domain = trim(domain)
    domain = tolower(domain)
    sub(/\.$/, "", domain)
    if (domain == "" ) next
    if (!valid_domain(domain)) {
      print $0 > "'"${INVALID_ENTRIES}"'"
      next
    }
    print domain
  }' "${input_file}" >> "${output_file}"
}

if [[ -z "${DB_PATH}" ]]; then
  if [[ -n "${PIHOLE_SSH_TARGET:-}" ]]; then
    SQL_BACKEND="ssh"
    require_cmd ssh
    DB_PATH="/etc/pihole/gravity.db"
    if ! run_sql "PRAGMA user_version;" >/dev/null 2>&1; then
      echo "Unable to query Pi-hole database over SSH at ${PIHOLE_SSH_TARGET} for ${DB_PATH}" >&2
      exit 1
    fi
  elif [[ -n "${CONTAINER}" ]]; then
    SQL_BACKEND="docker"
    if ! command -v docker >/dev/null 2>&1; then
      echo "docker not available; cannot access Pi-hole container without PIHOLE_GRAVITY_DB." >&2
      exit 1
    fi
    if ! docker exec -i "${CONTAINER}" test -x /usr/bin/pihole-FTL; then
      echo "pihole-FTL not found in container ${CONTAINER}." >&2
      exit 1
    fi
    if ! docker exec -i "${CONTAINER}" test -r /etc/pihole/gravity.db; then
      echo "gravity database not found in container ${CONTAINER} at /etc/pihole/gravity.db." >&2
      exit 1
    fi
    DB_PATH="/etc/pihole/gravity.db"
  else
    SQL_BACKEND="local"
    require_cmd pihole-FTL
    if [[ -r /etc/pihole/gravity.db ]]; then
      DB_PATH="/etc/pihole/gravity.db"
    else
      DB_PATH=""
    fi
  fi
fi

if [[ -z "${DB_PATH}" ]]; then
  if [[ -n "${CONTAINER}" ]]; then
    echo "Detected no local gravity database. Configure PIHOLE_CONTAINER or set PIHOLE_GRAVITY_DB." >&2
    echo "Examples:" >&2
    echo "  PIHOLE_CONTAINER=pihole ./scripts/export-pihole-blocklist.sh" >&2
    echo "  PIHOLE_SSH_TARGET=<user@host> ./scripts/export-pihole-blocklist.sh" >&2
  else
    echo "Pi-hole gravity database not found at /etc/pihole/gravity.db." >&2
    echo "If this is a remote Pi-hole, run this script there or set PIHOLE_GRAVITY_DB." >&2
  fi
  exit 1
fi

if ! command -v awk >/dev/null 2>&1; then
  echo "Missing required command: awk" >&2
  exit 1
fi

pi_version="$(run_sql "SELECT value FROM info WHERE property='VERSION';" 2>/dev/null | head -n 1 || true)"
if [[ -z "${pi_version}" ]]; then
  echo "Unable to read Pi-hole version from info table; continuing with direct schema checks." >&2
else
  echo "Pi-hole version detected: ${pi_version}"
fi

for table in gravity adlist domainlist; do
  if [[ -z "$(sqlite_has_table "${table}" | tr -d '\r')" ]]; then
    echo "Missing required table: ${table}" >&2
    exit 1
  fi
done

for pair in "gravity:domain" "gravity:adlist_id" "adlist:id" "adlist:enabled" "adlist:type" "domainlist:type" "domainlist:enabled" "domainlist:domain"; do
  table="${pair%%:*}"
  column="${pair##*:}"
  if ! sqlite_has_column "${table}" "${column}"; then
    echo "Missing required column ${column} in table ${table}" >&2
    exit 1
  fi
done

enabled_adlists="$(run_sql "SELECT COUNT(*) FROM adlist WHERE enabled=1;" | tr -d '\r')"
raw_gravity_entries="$(run_sql "SELECT COUNT(*) FROM gravity g JOIN adlist a ON a.id = g.adlist_id WHERE a.enabled=1 AND a.type=0;" | tr -d '\r')"
unique_gravity_domains="$(run_sql "SELECT COUNT(DISTINCT g.domain) FROM gravity g JOIN adlist a ON a.id = g.adlist_id WHERE a.enabled=1 AND a.type=0;" | tr -d '\r')"
exact_deny_count="$(run_sql "SELECT COUNT(DISTINCT domain) FROM domainlist WHERE enabled=1 AND type=1;" | tr -d '\r')"
exact_allow_count="$(run_sql "SELECT COUNT(*) FROM domainlist WHERE enabled=1 AND type=0;" | tr -d '\r')"
regex_deny_count="$(run_sql "SELECT COUNT(*) FROM domainlist WHERE enabled=1 AND type=3;" | tr -d '\r')"

run_sql "SELECT g.domain FROM gravity g JOIN adlist a ON a.id = g.adlist_id WHERE a.enabled=1 AND a.type=0;" > "${RAW_GRAVITY}"
run_sql "SELECT domain FROM domainlist WHERE enabled=1 AND type=1;" > "${RAW_DENY}"
run_sql "SELECT domain FROM domainlist WHERE enabled=1 AND type=0;" > "${RAW_ALLOW}"

normalize_domains "${RAW_GRAVITY}" "${NORM_GRAVITY}"
normalize_domains "${RAW_DENY}" "${NORM_DENY}"
normalize_domains "${RAW_ALLOW}" "${NORM_ALLOW}"

LC_ALL=C sort -u "${NORM_GRAVITY}" > "${GRAVITY_UNIQ}"
LC_ALL=C sort -u "${NORM_DENY}" > "${DENY_UNIQ}"
LC_ALL=C sort -u "${NORM_ALLOW}" > "${ALLOW_UNIQ}"

LC_ALL=C sort -u "${GRAVITY_UNIQ}" "${DENY_UNIQ}" > "${COMBINED}"
excluded_allow_count="$(comm -12 "${COMBINED}" "${ALLOW_UNIQ}" | tee "${TMP_DIR}/allow_overlap.txt" | wc -l | tr -d ' ')"

LC_ALL=C comm -23 "${COMBINED}" "${ALLOW_UNIQ}" > "${FINAL_SORTED}"
final_count="$(wc -l < "${FINAL_SORTED}" | tr -d ' ')"

total_normalized_lines="$(($(wc -l < "${NORM_GRAVITY}" | tr -d ' ') + $(wc -l < "${NORM_DENY}" | tr -d ' ')))"
duplicates_removed="$(("${total_normalized_lines}" - "$(wc -l < "${COMBINED}" | tr -d ' ')"))"
malformed_count="$(wc -l < "${INVALID_ENTRIES}" | tr -d ' ')"
file_size_bytes="$(wc -c < "${FINAL_SORTED}" | tr -d ' ')"

generated_utc="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

{
  echo "# Travis Mills Combined Pi-hole Blocklist"
  echo "# Generated automatically from enabled Pi-hole gravity lists and exact deny rules"
  echo "# Repository: travismills82/blocklists-ads"
  echo "# Generated: ${generated_utc}"
  echo "# Domains: ${final_count}"
  echo ""
  cat "${FINAL_SORTED}"
} > "${OUTPUT_TMP}"

mv "${OUTPUT_TMP}" "${OUTPUT_FILE}"

echo "Enabled adlists: ${enabled_adlists}"
echo "Raw gravity entries collected: ${raw_gravity_entries}"
echo "Unique gravity domains: ${unique_gravity_domains}"
echo "Enabled exact deny entries: ${exact_deny_count}"
echo "Enabled exact allow entries excluded: ${excluded_allow_count}"
echo "Enabled regex deny rules NOT included: ${regex_deny_count}"
echo "Duplicates removed: ${duplicates_removed}"
echo "Final unique domain count: ${final_count}"
echo "ads.txt size (bytes): ${file_size_bytes}"
echo "Malformed entries rejected: ${malformed_count}"
if [[ "${malformed_count}" -gt 0 ]]; then
  echo "Malformed examples:"
  sed -n '1,20p' "${INVALID_ENTRIES}"
fi
