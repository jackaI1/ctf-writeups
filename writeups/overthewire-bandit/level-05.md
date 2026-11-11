# Level 5: find a file by size and type

**Goal:** The password is in one file under `inhere` that is 1033 bytes, is human-readable, and is not executable.

## Steps

1. Use find with three filters: `find inhere -type f -size 1033c ! -executable`. The `c` suffix means bytes.
2. Read the one file it prints.

## What I learned

`find` can combine type, size and permission tests. Without the `c` suffix the size is in 512-byte blocks, which is an easy mistake.

Back to the [index](README.md).
