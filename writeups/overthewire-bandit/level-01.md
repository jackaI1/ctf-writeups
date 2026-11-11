# Level 1: a file named with a dash

**Goal:** Read a file called `-` in the home directory.

## Steps

1. Running `cat -` reads from standard input instead of the file, so the command waits forever.
2. Give the path explicitly: `cat ./-`. The `./` tells the shell this is a file in the current folder.

## What I learned

A leading dash is read as an option or as stdin. Writing `./` before the name (or `--`) avoids that. The script for this level is `scripts/bandit_step.sh 1 'cat ./-'`.

Back to the [index](README.md).
