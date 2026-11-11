# Level 9: printable text inside a binary file

**Goal:** `data.txt` is mostly binary. The password is a readable string after a run of equals signs.

## Steps

1. `strings data.txt` prints runs of printable characters.
2. Keep only the lines with `==`, then take the last one and its last field: `strings data.txt | grep '==' | tail -n 1 | awk '{print $NF}'`.

## What I learned

`strings` is a quick way to see the text inside a binary file, and the same filtering idea works on logs and memory dumps.

Back to the [index](README.md).
