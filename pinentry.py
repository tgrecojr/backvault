#!/app/.venv/bin/python
"""Pinentry stub for rbw.

rbw asks for three different credentials via pinentry during the
register + unlock flow:

  - "Client ID"       → BW_CLIENT_ID     (during `rbw register`)
  - "Client Secret"   → BW_CLIENT_SECRET (during `rbw register`)
  - "Master Password" → BW_PASSWORD      (during `rbw unlock`)

We dispatch based on the SETPROMPT / SETDESC text rbw sends before
each GETPIN. Both underscored (env-style) and no-underscore (bw-style)
env var names are accepted for the API-key creds.
"""

import os
import sys

CLIENT_ID = os.environ.get("BW_CLIENT_ID") or os.environ.get("BW_CLIENTID") or ""
CLIENT_SECRET = (
    os.environ.get("BW_CLIENT_SECRET") or os.environ.get("BW_CLIENTSECRET") or ""
)
PASSWORD = os.environ.get("BW_PASSWORD", "")


def _pick(prompt: str, desc: str) -> str:
    text = f"{prompt} {desc}".lower()
    if "client id" in text or "clientid" in text or "client_id" in text:
        return CLIENT_ID
    if "client secret" in text or "clientsecret" in text or "client_secret" in text:
        return CLIENT_SECRET
    return PASSWORD


def main() -> None:
    sys.stdout.write("OK Pleased to meet you\n")
    sys.stdout.flush()

    prompt = ""
    desc = ""

    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        parts = line.split(" ", 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "SETPROMPT":
            prompt = arg
            sys.stdout.write("OK\n")
        elif cmd == "SETDESC":
            desc = arg
            sys.stdout.write("OK\n")
        elif cmd == "GETPIN":
            value = _pick(prompt, desc)
            # Log which credential was served (length only, never the value)
            sys.stderr.write(
                f"pinentry: prompt={prompt!r} desc={desc!r} returned_len={len(value)}\n"
            )
            sys.stderr.flush()
            sys.stdout.write(f"D {value}\nOK\n")
            prompt = ""
            desc = ""
        elif cmd == "BYE":
            sys.stdout.write("OK closing connection\n")
            sys.stdout.flush()
            return
        else:
            sys.stdout.write("OK\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
