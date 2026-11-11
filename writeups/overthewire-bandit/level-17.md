# Level 17: comparing two password files

**Goal:** Log in as bandit17 with the key from level 16, then find the password that changed.

## Steps

1. Save the key locally, set `chmod 600`, and log in on port 2220: `ssh -i key17.pem -p 2220 bandit17@bandit.labs.overthewire.org`.
2. Run `diff passwords.old passwords.new`. The line marked `>` holds the new password for bandit18.

## What I learned

`diff` shows only what changed between two files. Keys can be used for more than one login, so they need the same care as passwords.

Back to the [index](README.md).
