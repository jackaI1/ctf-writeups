# Level 6: search the whole disk

**Goal:** The password is in a file owned by user bandit7 and group bandit6, 33 bytes long, somewhere on the server.

## Steps

1. Search from the root folder: `find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null`.
2. Send errors to `/dev/null` because most folders are not readable by this user and would bury the result.

## What I learned

Searching from `/` is slow and noisy. Ownership and size filters narrow the result, and redirecting stderr keeps the output readable.

Back to the [index](README.md).
