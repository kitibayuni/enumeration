#!/usr/bin/env python3
"""
mangle_leet.py
Reads words from stdin or a file and prints leetspeak/mangled variants.
Usage:
  cat words.txt | ./mangle_leet.py > variants.txt
  or
  ./mangle_leet.py words.txt > variants.txt
Options:
  --max N   : maximum variants per input word (default 0 = unlimited)
  --case    : include variants with first letter uppercase
"""
import sys, itertools, argparse

parser = argparse.ArgumentParser()
parser.add_argument('file', nargs='?', help='input file (optional, else read stdin)')
parser.add_argument('--max', type=int, default=0, help='max variants per word (0 = no limit)')
parser.add_argument('--case', action='store_true', help='also include capitalized-first-letter variants')
args = parser.parse_args()

# substitution map - add/remove entries as you like
MAP = {
    'a': ['a','@','4'],
    'b': ['b','8'],
    'c': ['c','('],
    'e': ['e','3'],
    'g': ['g','9'],
    'i': ['i','1','!','|'],
    'l': ['l','1','|'],
    'o': ['o','0'],
    's': ['s','$','5'],
    't': ['t','7'],
    'z': ['z','2'],
    # keep letters not listed as themselves only (no substitution)
}

def variants_for(word):
    # build substitution lists for each char
    lists = []
    for ch in word:
        low = ch.lower()
        if low in MAP:
            # preserve case by returning same-case variants where appropriate
            choices = MAP[low][:]
            # Also allow the original character as-is
            if ch not in choices:
                choices.insert(0, ch)
            # If original char is uppercase, capitalize choices' first char
            if ch.isupper():
                choices = [c.upper() if c.isalpha() else c for c in choices]
            lists.append(choices)
        else:
            lists.append([ch])
    # Cartesian product
    for i, combo in enumerate(itertools.product(*lists), start=1):
        yield ''.join(combo)
        if args.max and i >= args.max:
            break

def process_line(line):
    w = line.strip()
    if not w:
        return
    seen = set()
    # default variants
    for v in variants_for(w):
        if v not in seen:
            print(v); seen.add(v)
    # optionally also produce Capitalized-first variants
    if args.case:
        W = w[0].upper() + w[1:]
        for v in variants_for(W):
            if v not in seen:
                print(v); seen.add(v)

# input
if args.file:
    fh = open(args.file, 'r', encoding='utf-8', errors='ignore')
else:
    fh = sys.stdin

for line in fh:
    process_line(line)

if args.file:
    fh.close()
