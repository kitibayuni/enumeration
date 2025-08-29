#!/bin/bash

# This script starts out AGGRESSIVELY -- try not to use where stealth is essential

# check if IP is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

TARGET="$1"
HOSTNAME=$(echo "$TARGET" | tr -d '[:punct:]')  # remove punctuations for filename

# initial sweep
echo "Starting initial AGGRO sweep on $TARGET..."
nmap -p- --min-rate=1000 -T3 --max-retries 5 --min-rate 500 -n -Pn "$TARGET" -oG "${HOSTNAME}_initial-sweep-AGGRO.txt"

# extract ports
echo "Extracting open ports from initial AGGRO sweep for $TARGET..."
grep open "${HOSTNAME}_initial-sweep-AGGRO.txt" | grep -oP '\d+/open' | cut -d '/' -f1 | paste -sd, - > "${HOSTNAME}_ports-AGGRO.txt"

# running additional scan on open ports
PORTS=$(cat "${HOSTNAME}_ports-AGGRO.txt")

if [ -z "$PORTS" ]; then
    echo "[!] No open ports detected. Exiting."
    exit 0
fi

echo "Running detailed scan on open ports: $PORTS for $TARGET..."
nmap -sS -sV -O --script "default,vuln,discovery,safe" -p $PORTS "$TARGET" -T4 -n -Pn -oX "${HOSTNAME}_detailed-scan-AGGRO.xml"

# OUTPUT!
echo "Detailed AGGRO scan for $TARGET completed. Results saved to ${HOSTNAME}_detailed-scan-AGGRO.xml

