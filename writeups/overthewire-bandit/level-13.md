# Level 13: an SSH private key

**Goal:** Use a private key file to log in as the next user, bandit14, instead of a password.

## Steps

1. Copy the key to my computer, keeping it private: `ssh -p 2220 bandit13@bandit.labs.overthewire.org 'cat sshkey.private' > sshkey.private` and `chmod 600 sshkey.private`.
2. Log in with it: `ssh -i sshkey.private -p 2220 bandit14@bandit.labs.overthewire.org`.
3. Read the password: `cat /etc/bandit_pass/bandit14`. Then delete the local key with `rm sshkey.private`.

## What I learned

A private key can replace a password. The file must be readable only by its owner (`chmod 600`), and it must never be committed to Git. The `.gitignore` in this repo excludes `sshkey*` and `*.pem`.

Back to the [index](README.md).
