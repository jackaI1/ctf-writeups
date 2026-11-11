# Level 18: a command run without an interactive shell

**Goal:** Read the password for bandit19, even though the account logs you out right away.

## Steps

1. The account's `.bashrc` file ends the session as soon as you log in interactively.
2. Run one command over SSH instead: `scripts/bandit_step.sh 18 'cat readme'`. The command runs and the connection closes before the logout happens.

## What I learned

Login scripts only run for interactive sessions. Passing a command to `ssh` skips that path, which is why scripting over SSH needs one command per connection.

Back to the [index](README.md).
