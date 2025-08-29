#!/bin/bash
# Nmap Vulners Scan Script
# Usage: ./vulnscan.sh <target_ip>

if [ -z "$1" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

TARGET=$1
XML_OUT="scan_${TARGET}.xml"
HTML_OUT="scan_${TARGET}.html"

echo "[*] Running Nmap vulners scan against $TARGET..."
nmap -sV \
  --script "vulners,vuln" \
  --script-args mincvss=0 \
  -oX "$XML_OUT" \
  "$TARGET"

if [ $? -eq 0 ]; then
    echo "[*] Converting $XML_OUT to $HTML_OUT..."
    xsltproc /usr/share/nmap/nmap.xsl "$XML_OUT" -o "$HTML_OUT"

    if [ $? -eq 0 ]; then
        echo "[+] Scan complete! Results saved as:"
        echo "    XML:  $XML_OUT"
        echo "    HTML: $HTML_OUT"
    else
        echo "[!] Failed to convert XML to HTML. Check if xsltproc and nmap.xsl exist."
    fi
else
    echo "[!] Nmap scan failed."
fi
