#!/app/.venv/bin/python
"""Minimal pinentry stub for rbw.

Implements just enough of the Assuan pinentry protocol to hand the master
password (from the BW_PASSWORD env var) back to rbw during `rbw unlock`.
"""

import os
import sys


def main() -> None:
    password = os.environ.get("BW_PASSWORD", "")

    sys.stdout.write("OK Pleased to meet you\n")
    sys.stdout.flush()

    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        cmd = line.split(" ", 1)[0].upper()
        if cmd == "GETPIN":
            sys.stdout.write(f"D {password}\nOK\n")
        elif cmd == "BYE":
            sys.stdout.write("OK closing connection\n")
            sys.stdout.flush()
            return
        else:
            # SETPROMPT, SETDESC, SETTITLE, OPTION, etc. — acknowledge and move on.
            sys.stdout.write("OK\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
