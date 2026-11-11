# Level 4: find the one readable file

**Goal:** Several files in a folder are binary and only one is plain text.

## Steps

1. List the folder: `ls -la inhere`. There are files named `-file00` to `-file09`.
2. Ask `file` what each one holds: `file ./inhere/-file*`.
3. Read the one reported as `ASCII text`: `cat ./inhere/-file07` (the number may differ on your run).

## What I learned

`file` reads the first bytes of a file to guess its type. It is a fast way to triage many files before opening them.

Back to the [index](README.md).
