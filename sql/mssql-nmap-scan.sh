#!/usr/bin/env bash
# mssql-nmap-scan.sh
# Wrapper to run a set of MSSQL NSE scripts against a target.
#
# Usage:
#   ./mssql-nmap-scan.sh -t <target> [-p <port>] [-u <username>] [-P <password>] [-i <instance>] [--extra "<nmap-args>"]
#
# Examples:
#   ./mssql-nmap-scan.sh -t 10.129.201.248
#   ./mssql-nmap-scan.sh -t db.example.org -p 1434 -u sa -P "P@ssw0rd" -i MSSQLSERVER
#   sudo ./mssql-nmap-scan.sh -t 10.0.0.5 --extra "-Pn -T4"

set -euo pipefail

# Defaults
PORT=1433
USER="sa"
PASS=""
INSTANCE="MSSQLSERVER"
EXTRA_ARGS=""

show_help() {
  cat <<EOF
mssql-nmap-scan.sh - run MSSQL nmap NSE scripts

Required:
  -t <target>           target IP or hostname

Optional:
  -p <port>             TCP port for MSSQL (default: ${PORT})
  -u <username>         MSSQL username (default: ${USER})
  -P <password>         MSSQL password (default: empty)
  -i <instance>         MSSQL instance name (default: ${INSTANCE})
  --extra "<nmap-args>" Extra nmap arguments you want appended (quoted)
  -h, --help            Show this help

Examples:
  ./mssql-nmap-scan.sh -t 10.129.201.248
  sudo ./mssql-nmap-scan.sh -t db.host -p 1433 -u sa -P '' -i MSSQLSERVER --extra "-Pn -T4"
EOF
}

# parse args
if [[ $# -eq 0 ]]; then
  show_help
  exit 1
fi

TARGET=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t) TARGET="$2"; shift 2;;
    -p) PORT="$2"; shift 2;;
    -u) USER="$2"; shift 2;;
    -P) PASS="$2"; shift 2;;
    -i) INSTANCE="$2"; shift 2;;
    --extra) EXTRA_ARGS="$2"; shift 2;;
    -h|--help) show_help; exit 0;;
    *) echo "Unknown argument: $1"; show_help; exit 2;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "ERROR: target (-t) is required."
  show_help
  exit 2
fi

# Check for nmap
if ! command -v nmap &>/dev/null; then
  echo "ERROR: nmap is not installed or not in PATH."
  exit 3
fi

# Build the list of NSE scripts we want to run
SCRIPTS=(
  ms-sql-info
  ms-sql-empty-password
  ms-sql-xp-cmdshell
  ms-sql-config
  ms-sql-ntlm-info
  ms-sql-tables
  ms-sql-hasdbaccess
  ms-sql-dac
  ms-sql-dump-hashes
)
SCRIPT_LIST=$(IFS=,; echo "${SCRIPTS[*]}")

# Build script-args string (only include empty password as literal if user passed empty)
# Note: keep password argument (may be empty), and properly escape/quote when passing to bash.
SCRIPT_ARGS="mssql.instance-port=${PORT},mssql.username=${USER},mssql.password=${PASS},mssql.instance-name=${INSTANCE}"

# Final nmap command (array form to avoid word-splitting issues)
NMAP_CMD=(sudo nmap -sV -p "${PORT}" --script "${SCRIPT_LIST}" --script-args "${SCRIPT_ARGS}")

# Append extra args if provided (split on whitespace safely using eval into array)
if [[ -n "$EXTRA_ARGS" ]]; then
  # shellcheck disable=SC2086
  read -r -a EXTRA_ARRAY <<< "${EXTRA_ARGS}"
  NMAP_CMD+=("${EXTRA_ARRAY[@]}")
fi

NMAP_CMD+=("$TARGET")

# Print the command we're about to run (safe-ish; password printed if provided)
echo "Running:"
printf ' %q' "${NMAP_CMD[@]}"
echo
echo

# Run the command
"${NMAP_CMD[@]}"
