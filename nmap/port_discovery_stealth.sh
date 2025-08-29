#!/bin/bash

# This script performs a stealthier NMAP scan

# check if IP is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

TARGET="$1"
HOSTNAME=$(echo "$TARGET" | tr -d '[:punct:]')  # remove punctuations for filename

# decoy list
DECOYS="192.168.1.10,192.168.1.25,192.168.1.50,192.168.1.100,192.168.1.150,192.168.1.200,10.0.0.5,10.0.0.10,10.0.0.25,10.0.0.50,10.0.0.75,10.0.0.100,172.16.0.10,172.16.0.20,172.16.0.30,172.16.0.40,172.16.0.50,172.16.0.60,172.16.0.70,172.16.0.80,203.0.113.10,203.0.113.20,203.0.113.30,203.0.113.40,203.0.113.50,198.51.100.5,198.51.100.10,198.51.100.15,198.51.100.20,198.51.100.25,198.51.100.30,198.51.100.35,198.51.100.40,198.51.100.45,198.51.100.50,203.0.113.60,203.0.113.70,203.0.113.80,203.0.113.90,203.0.113.100,192.0.2.10,192.0.2.20,192.0.2.30,192.0.2.40,192.0.2.50,192.0.2.60,192.0.2.70,192.0.2.80,192.0.2.90,192.0.2.100"

# initial sweep
echo "Starting initial STEALTH sweep on $TARGET..."
nmap -p- --min-rate=200 -T1 --max-retries 2 --min-rate 50 --scan-delay 500ms --max-parallelism 1 -D $DECOYS --data-length 25 -n -Pn "$TARGET" -oG "${HOSTNAME}_initial-sweep-STEALTH.txt"

# extract ports
echo "Extracting open ports from initial STEALTH sweep for $TARGET..."
grep open "${HOSTNAME}_initial-scan-STEALTH.txt" | grep -oP '\d+/open' | cut -d '/' -f1 | paste -sd, - > "${HOSTNAME}_ports-STEALTH.txt"

# running additional scan on open ports
PORTS=$(cat "${HOSTNAME}_ports-STEALTH.txt")

if [ -z "$PORTS" ]; then
    echo "[!] No open ports detected. Exiting."
    exit 0
fi

echo "Running detailed scan on open ports: $PORTS for $TARGET..."
nmap --max-retries 2 --min-rate 50 --max-rate 200 --scan-delay 500ms --max-parallelism 1 --data-length 25 -D $DECOYS -sS -sV -O --script "discovery,safe" -p $PORTS "$TARGET" -T1 -n -Pn -oX "${HOSTNAME}_detailed-scan-AGGRO.xml"

# OUTPUT!
echo "Detailed STEALTH scan for $TARGET completed. Results saved to ${HOSTNAME}_detailed-scan-STEALTH.xml

