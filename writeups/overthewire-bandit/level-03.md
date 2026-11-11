# Level 3: a hidden file in a folder

**Goal:** Find the password in a folder that only shows up with `ls -a`.

## Steps

1. `ls` hides names that start with a dot, so I listed everything: `ls -la inhere`.
2. The file is named `...Hiding-From-You`. Read it with `cat inhere/...Hiding-From-You`.

## What I learned

Files that start with a dot are hidden by default. `ls -a` or `ls -la` shows them. Dots can also be part of ordinary names.

Back to the [index](README.md).
