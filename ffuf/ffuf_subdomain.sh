#!/bin/bash

# FFUF subdomain enumeration

# check for domain and worlist args
if [ "$#" -ne 3 ]; then
	echo "Usage: $0 <domain> <wordlist> <protocol>"
	echo "Example: ./ffuf_subdomain.sh example.com rockyou.txt https"
	exit 1
fi

DOMAIN="$1"
WORDLIST="$2"
PROTOCOL="$3"
OUTPUT="ffuf_subdomains_$DOMAIN.json"

ffuf \
  -w "$WORDLIST" \
  -u "$PROTOCOL://FUZZ.$DOMAIN" \
  -H "Host: FUZZ.$DOMAIN" \
  -mc 200,301,302 \
  -t 50 \
  -o "$OUTPUT" \
  -of json