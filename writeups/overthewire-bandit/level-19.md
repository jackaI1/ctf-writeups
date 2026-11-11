# Level 19: a setuid helper program

**Goal:** Use a helper that runs with another user's rights to read a file that the current user cannot read.

## Steps

1. `bandit20-do` is a program owned by bandit20 with the setuid bit set, so it runs with bandit20's rights.
2. Run `./bandit20-do cat /etc/bandit_pass/bandit20`. The helper runs the command as bandit20 and prints the password.

## What I learned

A setuid program runs with its owner's permissions. This is useful for admin tools, and it is dangerous when a program lets you run arbitrary commands. Always check what a setuid program actually runs.

Back to the [index](README.md).
