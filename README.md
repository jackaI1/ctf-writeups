# ctf-writeups
Project by Jack Lai

I built a set of practice-puzzle write-ups and small tools because I was working through OverTheWire Bandit and kept losing the exact commands that solved each level. Some puzzles also hide a message under several layers of encoding and compression, and peeling those layers by hand was slow and easy to get wrong.

The write-ups show, step by step, how I solved each Bandit level from 0 to 19. The tools do the repeated work: they decode layered files, search web and login logs for attacks, and read network captures so I can follow a conversation and find text in it. The tools run on a normal computer with Python and need no account. Only the Bandit script needs the game's own login, and it is optional.

## What is in here

- [Bandit write-ups](writeups/overthewire-bandit/README.md): one page per level, with the goal, the commands and what I learned. The passwords are not published.
- `ctf_tools/`: three Python tools, `decode`, `logsearch` and `pcap`.
- `scripts/bandit_step.sh`: a Bash script that runs one command as a Bandit level and saves the next password to a file outside this repository.
- `examples/`: small made-up log, capture and encoded files so you can try the tools without downloading anything.
- [docs/tools.md](docs/tools.md): the full options for each tool.

## Try it

You need Python 3.10 or newer. From the project folder:

```sh
python -m ctf_tools.decode examples/layered.hex
python -m ctf_tools.logsearch examples/access.log --preset traversal
python -m ctf_tools.logsearch examples/auth.log --preset ssh-failed
python -m ctf_tools.pcap examples/sample.pcap summary
python -m ctf_tools.pcap examples/sample.pcap follow --src 192.0.2.10 --sport 51000 --dst 192.0.2.20 --dport 9000
```

The first command peels three layers (a hexdump, bzip2 and gzip) and prints the message inside. The `follow` command rebuilds a TCP conversation from its packets, which is how the flag in the sample capture is split across several packets.

To run the tests:

```sh
python -m pip install -e ".[test]"
python -m pytest -q
shellcheck scripts/*.sh
```

## How it works

The decoder looks at the start of the data and tries each layer it knows: text forms such as hexdump and base64, and binary formats such as gzip, bzip2 and tar. A layer is kept only if the result looks like text or has the right file signature, so random data is not mistaken for a message. It repeats until nothing fits, and it stops if the output gets too large. ROT13 is only used when you ask for it, because it turns readable text into other readable text.

The log search reads a web or login log one line at a time, so a big file is fine. It uses a regular expression, which is a compact pattern such as `\.\./` for directory-traversal attempts. Then it counts the source addresses and paths of the matching lines, so I can see who is attacking without reading every line.

The packet tool reads the classic capture format directly, and it understands the Ethernet, IPv4, TCP and UDP layers. For a TCP stream it puts the segments back in order and drops the ones that were sent twice. Looking at each packet alone would miss a flag split across packets, so the follow command matters.

The Bandit script logs in with the password saved in a file and gives the password to SSH through its own password helper, so the password never appears in a command line or in the output. It saves the next password only if the command printed exactly one password-shaped line.

## Design notes

- Standard library only for the Python tools, so there is nothing to install beyond Python.
- The tools are tested with small fixtures built inside the tests, including a fake `ssh` for the Bash script.
- The continuous integration (CI) workflow runs the tests on Python 3.10 and 3.13, and runs ShellCheck, a linter for shell scripts.
- Passwords, keys and password folders are excluded in `.gitignore`.
- I have only practised on Bandit and the made-up examples here. I have not entered any live competition.
