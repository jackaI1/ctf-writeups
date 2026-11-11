# Level 15: talking TLS to a service

**Goal:** Send the level 15 password to a TLS service on port 30001.

## Steps

1. Log in as bandit15 and run `cat /etc/bandit_pass/bandit15 | timeout 5 openssl s_client -quiet -connect localhost:30001`.
2. The service answers with the level 16 password.

## What I learned

`openssl s_client` is a TLS client. `-quiet` hides the certificate details, and `timeout` stops it if the service never closes the connection.

Back to the [index](README.md).
