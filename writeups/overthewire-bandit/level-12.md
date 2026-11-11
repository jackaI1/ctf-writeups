# Level 12: layers of hexdump, compression and archives

**Goal:** `data.txt` is a hexdump of a file that was compressed and archived many times, and the password is at the bottom.

## Steps

1. Copy the file down without changing it: `scripts/bandit_step.sh --show 12 'cat data.txt' > level12.hex`.
2. Run the layer peeler: `python -m ctf_tools.decode level12.hex --output level13.bin`. It printed nine steps: an `xxd` hexdump, then gzip, bzip2, gzip, tar, tar, bzip2, tar and gzip, ending in ASCII text.
3. The result is a 49-byte file holding `The password is ` and the 32-character password. Read the last 32 letters or digits and save them as `pass13` in the password folder.

## What I learned

Real challenges often hide data in layers. Doing this by hand meant checking `file` after every step, so I wrote `ctf_tools/decode.py` to repeat the check and keep a record of each step. It also refuses to expand data past a size limit, so a file that expands forever cannot fill the disk.

Back to the [index](README.md).
