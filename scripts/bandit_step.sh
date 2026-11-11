#!/usr/bin/env bash
# Run one command as an OverTheWire Bandit level and save the next password.
#
# Usage:
#   scripts/bandit_step.sh LEVEL 'COMMAND'
#   scripts/bandit_step.sh 12 'cat data.txt'
#   scripts/bandit_step.sh --show 12 'ls -la'     # print the output, save nothing
#
# The password for LEVEL is read from $BANDIT_PASS_DIR/passLEVEL (one line).
# The command's output must be exactly one 32-character password line. If it is,
# the line is saved as passNEXT so the next level can use it. Passwords are never
# printed by this script, and the directory defaults to a folder outside this repo.
#
# Environment:
#   BANDIT_PASS_DIR  where password files live (default: ~/.config/ctf-writeups/bandit)
#   BANDIT_HOST      default bandit.labs.overthewire.org
#   BANDIT_PORT      default 2220
#   SSH_BIN          ssh binary to use (default: ssh); tests replace it with a fake

set -euo pipefail

usage() {
  echo "usage: $0 [--show] LEVEL 'COMMAND'" >&2
  exit 2
}

show=0
if [[ "${1:-}" == "--show" ]]; then
  show=1
  shift
fi
[[ $# -eq 2 ]] || usage
level="$1"
command_text="$2"
[[ "$level" =~ ^[0-9]+$ ]] || { echo "LEVEL must be a number" >&2; exit 2; }

pass_dir="${BANDIT_PASS_DIR:-$HOME/.config/ctf-writeups/bandit}"
host="${BANDIT_HOST:-bandit.labs.overthewire.org}"
port="${BANDIT_PORT:-2220}"
ssh_bin="${SSH_BIN:-ssh}"
next=$((level + 1))

password_file="$pass_dir/pass$level"
[[ -f "$password_file" ]] || { echo "missing $password_file; save the level $level password there first" >&2; exit 1; }

# OpenSSH asks for a password through SSH_ASKPASS. This helper prints the stored
# password without putting it on the command line or in the output.
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
askpass="$work_dir/askpass.sh"
cat > "$askpass" <<'ASKPASS'
#!/bin/sh
printf '%s\n' "$BANDIT_PASS"
ASKPASS
chmod 700 "$askpass"

output_file="$work_dir/output.txt"
set +e
BANDIT_PASS="$(tr -d '\r\n' < "$password_file")" \
  SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force \
  "$ssh_bin" -p "$port" -o ConnectTimeout=15 -o LogLevel=ERROR \
  "bandit$level@$host" "$command_text" < /dev/null > "$output_file" 2> "$work_dir/stderr.txt"
status=$?
set -e

# Remove blank lines and carriage returns, then require exactly one password.
grep -v '^[[:space:]]*$' "$output_file" | tr -d '\r' > "$work_dir/clean.txt" || true
lines=$(wc -l < "$work_dir/clean.txt" | tr -d ' ')

if [[ $status -ne 0 ]]; then
  echo "ssh exited with status $status; the password was not saved" >&2
  head -c 300 "$work_dir/stderr.txt" >&2 || true
  exit 1
fi

if [[ $show -eq 1 ]]; then
  cat "$work_dir/clean.txt"
  exit 0
fi

if [[ "$lines" == "1" ]] && grep -Eq '^[A-Za-z0-9]{32}$' "$work_dir/clean.txt"; then
  next_file="$pass_dir/pass$next"
  if [[ -e "$next_file" ]]; then
    echo "$next_file already exists; delete it first to overwrite" >&2
    exit 1
  fi
  umask 077
  cp "$work_dir/clean.txt" "$next_file"
  echo "saved the level $next password to $next_file (not printed)"
else
  # The output is not shown: it may contain a password that should not reach the terminal.
  echo "output was not exactly one 32-character password line ($lines non-blank lines); nothing saved" >&2
  exit 1
fi
