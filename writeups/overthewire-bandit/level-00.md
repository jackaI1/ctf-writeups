# Level 0: logging in and reading a file

**Goal:** Log in to the game server and read the password for level 1.

## Steps

1. Connect with `ssh -p 2220 bandit0@bandit.labs.overthewire.org`. The starting password is on the game page, so I did not copy it here.
2. List the home directory with `ls -la`, then read the file the game left for me: `cat readme`.
3. The file contains the level 1 password. I saved it as a file named `pass1` in my password folder, outside this repository, so the scripts can reuse it.

## What I learned

The game uses SSH on port 2220, not the usual port 22. Each level's password is stored in a file that the next level's user can read, so the goal is to find it with normal shell commands.

Back to the [index](README.md).
