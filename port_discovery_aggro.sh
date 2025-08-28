#!/bin/bash

# This script starts out AGGRESSIVELY -- try not to use where stealth is essential

# Check if the user provided a target
if [ -z "$1" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

TARGET="$1"

# fast scan
echo "Starting initial fast scan on $TARGET..."
nmap -p- --min-rate=1000 -T4 -n -Pn "$TARGET" -oG initial-scan.txt

# Step 2: Extract open ports from the initial scan
echo "Extracting open ports from initial scan..."
grep open initial-scan.txt | grep -oP '\d+/open' | cut -d '/' -f1 | paste -sd, - > ports.txt

# Step 3: Run a detailed scan on the discovered open ports
PORTS=$(cat ports.txt)

echo "Running detailed scan on open ports: $PORTS..."
nmap -sS -sV -O -p $PORTS "$TARGET" --scan-delay 200ms --max-retries 2 -T2 -n -Pn -oX detailed-scan.xml

# Step 4: Output the results
echo "Detailed scan completed. Results saved to detailed-scan.xml"

