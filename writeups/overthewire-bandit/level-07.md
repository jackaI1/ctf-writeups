# Level 7: find a word in a big file

**Goal:** `data.txt` is large. Find the password next to the word `millionth`.

## Steps

1. Search for the word: `grep millionth data.txt`. The line has a tab between the word and the password.
2. Print only the second field: `grep millionth data.txt | awk '{print $2}'`.

## What I learned

`grep` filters lines by a pattern. `awk` splits a line into fields, which is useful for key and value files.

Back to the [index](README.md).
