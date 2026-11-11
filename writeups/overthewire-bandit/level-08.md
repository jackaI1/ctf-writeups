# Level 8: find the one line that appears once

**Goal:** Every line in `data.txt` repeats except one.

## Steps

1. `uniq` only compares neighbouring lines, so sort first: `sort data.txt | uniq -u`.
2. `-u` prints only lines that appear exactly once.

## What I learned

`uniq` needs sorted input. Piping `sort` into `uniq` is a common pattern for counting or de-duplicating lines.

Back to the [index](README.md).
