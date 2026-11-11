# Level 2: spaces in a file name

**Goal:** Read a file whose name contains spaces and starts with two dashes.

## Steps

1. List the directory with `ls -la` to see the exact name.
2. Quote the name so the shell keeps the spaces and the leading dashes: `cat ./'--spaces in this filename--'`.

## What I learned

Shell words split on spaces. Single quotes keep a name together, and the `./` keeps the leading dashes from being read as options.

Back to the [index](README.md).
