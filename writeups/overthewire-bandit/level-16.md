# Level 16: find the one port that answers

**Goal:** Find which port between 31000 and 32000 speaks TLS and accepts the level 16 password.

## Steps

1. Run the scan on the server: `pw=$(cat /etc/bandit_pass/bandit16); for port in $(seq 31000 32000); do if echo "$pw" | timeout 2 openssl s_client -quiet -connect localhost:$port 2>/dev/null | grep -q 'BEGIN OPENSSH PRIVATE KEY'; then echo "$port"; break; fi; done`. Each attempt waits at most two seconds.
2. Port 31790 replied `Correct!` followed by an SSH private key, not a password. That key is for bandit17.

## What I learned

A port scan can be a shell loop with a timeout. I checked the reply for a marker string (`BEGIN OPENSSH PRIVATE KEY`) rather than reading the whole output.

Back to the [index](README.md).
