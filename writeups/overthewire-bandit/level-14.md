# Level 14: sending a password to a local service

**Goal:** Send the level 14 password to a service on port 30000 and receive the level 15 password.

## Steps

1. Log in as bandit14, then run `cat /etc/bandit_pass/bandit14 | nc -w 3 localhost 30000 | grep -E '^[A-Za-z0-9]{32}$'`.
2. The service replies `Correct!` and the next password. The grep keeps only the password line.

## What I learned

`nc` (netcat) opens a plain TCP connection. `-w 3` stops it after three seconds of silence, so the command does not hang. Grep is used to pick the one line that matters.

Back to the [index](README.md).
