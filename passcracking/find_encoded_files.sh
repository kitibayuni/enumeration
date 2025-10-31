#!/usr/bin/env bash
# find_encoded_files.sh
# Usage: ./find_encoded_files.sh [-p start_path] [-o output.txt] [-e "extlist"]
# Default start_path: /
# Default extlist: .xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*
# Examples:
#   ./find_encoded_files.sh -o results.txt
#   ./find_encoded_files.sh -p /home -o out.txt

set -euo pipefail

START="/"
OUT=""
# default extensions (literal tokens, * allowed at end)
EXT_LIST=( ".xls" ".xls*" ".xltx" ".od*" ".doc" ".doc*" ".pdf" ".pot" ".pot*" ".pp*" )

# Excluded path substrings (grep -v will filter them out)
EXCLUDE_RE="/usr/lib|usr/share|usr/fonts|/proc|/sys|/dev|/run|/var/lib|core"

usage() {
  cat <<USAGE
Usage: $0 [-p start_path] [-o output.txt] [-e "ext1 ext2 ..."] [-h]
  -p start path (default /)
  -o write results to output file (also prints to stdout)
  -e override extensions list (space-separated quoted string)
  -h show this help
USAGE
  exit 1
}

# parse args
while getopts ":p:o:e:h" opt; do
  case "$opt" in
    p) START="$OPTARG" ;;
    o) OUT="$OPTARG" ;;
    e) IFS=' ' read -r -a EXT_LIST <<< "$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

# function to append to file if OUT set
maybe_write() {
  if [[ -n "$OUT" ]]; then
    printf "%s\n" "$1" >> "$OUT"
  fi
}

# start new output file if requested
if [[ -n "$OUT" ]]; then
  : > "$OUT" || { echo "Cannot write to $OUT"; exit 2; }
fi

# Main loop: for each extension pattern, use find -iname "*pattern"
# We avoid shell glob expansion by quoting "*${ext}".
# We use -xdev (do not cross filesystem boundaries) by default to avoid network mounts; remove if you want to cross.
# We also filter results with grep -v for excluded substrings (keeps script simple and readable).
echo "Starting scan at: $START"
maybe_write "Scan start: $(date) at path: $START"
for ext in "${EXT_LIST[@]}"; do
  echo
  echo "File extension pattern: $ext"
  maybe_write ""
  maybe_write "File extension pattern: $ext"

  # Build the find pattern: case-insensitive name match
  # If ext contains a literal '*' at the end (e.g. .xls*), find -iname "*\.xls*" still works.
  # Use -type f to look for files only.
  # Redirect permission errors to /dev/null.
  find "$START" -xdev -type f -iname "*${ext}" 2>/dev/null \
    | grep -v -E "$EXCLUDE_RE" \
    | while IFS= read -r file; do
        printf "%s\n" "$file"
        maybe_write "$file"
      done
done

echo
echo "Done. Results printed above."
if [[ -n "$OUT" ]]; then
  echo "Results also written to: $OUT"
fi
