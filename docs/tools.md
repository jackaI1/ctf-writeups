# Tool reference

These tools use only the Python standard library, so there is nothing to install beyond Python 3.10 or newer. The tests need `pytest`.

## Decoding layers: `ctf_tools.decode`

```sh
python -m ctf_tools.decode examples/layered.hex
python -m ctf_tools.decode level12.hex --output level13.bin
python -m ctf_tools.decode secret.txt --rot13 --max-steps 40
```

The tool tries each known layer on the current data and keeps the first one that fits. It understands:

- `xxd` style hexdumps (`00000000: 1f8b 0808 ...  ...`) and plain hex strings
- base64
- percent-encoded URLs
- gzip, bzip2, xz and zip, each with a size limit
- tar archives and zip files that hold exactly one file

A layer is accepted only if its output looks like text or matches a known file signature. This stops random data from being decoded into nonsense. ROT13 is off by default because it turns readable text into other readable text. The `--rot13` option uses it only when no other layer fits and it produces more common English words.

Each step is printed to standard error with its sizes, so you can see exactly what was done. The `--max-output-mb` option (10 MB by default) and `--max-steps` (25 by default) stop a file that keeps expanding from running forever.

## Log search: `ctf_tools.logsearch`

```sh
python -m ctf_tools.logsearch examples/access.log --preset traversal
python -m ctf_tools.logsearch examples/auth.log --preset ssh-failed --top 5
python -m ctf_tools.logsearch /var/log/nginx/access.log.1.gz --match 'union.+select' --status 500 --json
```

Presets are `traversal` (`../` and its encoded forms), `sqli`, `xss`, `scanner` (common probes such as `/.env`) and `ssh-failed`. Plain `.gz` files are read directly, and lines are streamed, so a large log is never loaded whole. The summary lists the top sources, top paths and status counts, then prints the first matching lines with their line numbers.

## Packet inspection: `ctf_tools.pcap`

```sh
python -m ctf_tools.pcap examples/sample.pcap summary
python -m ctf_tools.pcap examples/sample.pcap follow --src 192.0.2.10 --sport 51000 --dst 192.0.2.20 --dport 9000
python -m ctf_tools.pcap examples/sample.pcap grep 'flag\{[^}]*\}'
```

`summary` counts packets per TCP or UDP flow. `follow` rebuilds one TCP direction in sequence order and drops retransmitted bytes. `grep` searches each packet's payload separately, so a string split across packets will not match. Use `follow` for those. Only classic `.pcap` files with Ethernet frames are read. Convert `.pcapng` files first with `editcap -F pcap input.pcapng output.pcap` from Wireshark.

## Bandit password helper: `scripts/bandit_step.sh`

See the [Bandit index](../writeups/overthewire-bandit/README.md#reproducing-the-steps-with-the-scripts). The script uses OpenSSH's `SSH_ASKPASS` mechanism, so the password never appears on the command line, in shell history or in its output. It also refuses to overwrite a saved password.

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `BANDIT_PASS_DIR` | `~/.config/ctf-writeups/bandit` | where `passN` files are kept |
| `BANDIT_HOST` | `bandit.labs.overthewire.org` | game server |
| `BANDIT_PORT` | `2220` | game SSH port |
| `SSH_BIN` | `ssh` | ssh binary, replaced by a fake one in the tests |

## Running the tests and the linter

```sh
python -m pip install -e ".[test]"
python -m pytest -q
shellcheck scripts/*.sh
```

The Bash test runs the real script against a fake `ssh` that checks the password the same way OpenSSH does, so no network access is needed.
