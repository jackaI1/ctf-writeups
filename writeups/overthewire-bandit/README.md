# OverTheWire Bandit: written solutions

Bandit is a free practice game from [OverTheWire](https://overthewire.org/wargames/bandit/). Each level gives you one password, and the password unlocks the next level. Every level teaches one Linux or security idea, such as reading odd file names, searching a disk, decoding text or talking to a network service.

I worked through levels 0 to 19 and wrote down the commands for each one. Each page below states the goal, the exact steps, and what I learned. I do not publish the passwords or keys, so the pages show how to find them rather than giving the answers away. If you are still playing, try a level before you open its page.

I have practised on this game only. I have not entered any live competition.

## The levels

| Level | Idea | Page |
| --- | --- | --- |
| 0 | Logging in over SSH on a non-standard port | [level-00.md](level-00.md) |
| 1 | File names that start with a dash | [level-01.md](level-01.md) |
| 2 | File names with spaces | [level-02.md](level-02.md) |
| 3 | Hidden files | [level-03.md](level-03.md) |
| 4 | Finding the readable file with `file` | [level-04.md](level-04.md) |
| 5 | Finding a file by size and type with `find` | [level-05.md](level-05.md) |
| 6 | Searching the whole disk by owner and size | [level-06.md](level-06.md) |
| 7 | Filtering lines with `grep` and `awk` | [level-07.md](level-07.md) |
| 8 | Finding the unique line with `sort` and `uniq` | [level-08.md](level-08.md) |
| 9 | Printable text inside a binary file with `strings` | [level-09.md](level-09.md) |
| 10 | Base64 | [level-10.md](level-10.md) |
| 11 | ROT13 | [level-11.md](level-11.md) |
| 12 | Peeling many layers of hexdump, compression and archives | [level-12.md](level-12.md) |
| 13 | Logging in with an SSH private key | [level-13.md](level-13.md) |
| 14 | Sending a password to a local network service with `nc` | [level-14.md](level-14.md) |
| 15 | Talking TLS to a service with `openssl s_client` | [level-15.md](level-15.md) |
| 16 | Scanning a port range for the one service that answers | [level-16.md](level-16.md) |
| 17 | Comparing two files with `diff` | [level-17.md](level-17.md) |
| 18 | Running one command when the login shell logs you out | [level-18.md](level-18.md) |
| 19 | Using a setuid helper that runs as another user | [level-19.md](level-19.md) |

## Reproducing the steps with the scripts

The scripts keep each password in a file outside this repository, so nothing secret is committed. Put the password you already have into `pass<level>` in a folder such as `~/.config/ctf-writeups/bandit`, then:

```sh
export BANDIT_PASS_DIR="$HOME/.config/ctf-writeups/bandit"
scripts/bandit_step.sh --show 0 'cat readme'     # print the output, save nothing
scripts/bandit_step.sh 0 'cat readme'            # save the next password if the output is exactly one password line
```

The script refuses to save anything unless the output is exactly one 32-character line, and it never prints a password. Levels 13 and 15 to 17 use a key or a local service, so their pages show the commands to run directly. The decoder used in level 12 is documented in [docs/tools.md](../../docs/tools.md).
