#!/bin/bash

# FFUF recursive path enumeration

# check for domain and wordlist args
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <domain> <wordlist> <protocol>"
    echo "Example: ./ffuf_path.sh example.com directories.txt https"
    exit 1
fi

DOMAIN="$1"
WORDLIST="$2"
PROTOCOL="$3"
OUTPUT="ffuf_paths_$DOMAIN.json"

# run FFUF with recursion
ffuf -w "$WORDLIST" \
     -u "$PROTOCOL://$DOMAIN/FUZZ" \
     -mc 200,301,302 \
     -t 50 \
     -recursion \
     -recursion-depth 3 \
     -o "$OUTPUT" \
     -of json
