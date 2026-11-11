# Level 11: ROT13

**Goal:** `data.txt` is ROT13 encoded: each letter is shifted 13 places.

## Steps

1. Rotate the letters back with `tr`: `tr 'A-Za-z' 'N-ZA-Mn-za-m' < data.txt`.
2. Take the last word of the result.

## What I learned

ROT13 is its own inverse, so the same command encodes and decodes. It hides text from a quick glance but protects nothing.

Back to the [index](README.md).
