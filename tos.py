#!/usr/bin/env python3
"""Build a v4-mapped IPv6 TCP socket, setsockopt(IP_TOS and/or IPV6_TCLASS),
then connect + send so the marking (if any) shows up on the wire.

server:  python3 mapped_tos.py server
client:  python3 mapped_tos.py client --opt tos    --val 0xb8
         python3 mapped_tos.py client --opt tclass --val 0xb8
         python3 mapped_tos.py client --opt both   --val 0xb8
"""
import argparse, socket, sys, time

IP_TOS      = getattr(socket, "IP_TOS", 1)
IPV6_TCLASS = getattr(socket, "IPV6_TCLASS", 67)


def server(a):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)   # dual-stack
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("::", a.port))
    s.listen(8)
    print(f"[srv] listening :::{a.port} (dual-stack)", flush=True)
    while True:
        c, peer = s.accept()
        print(f"[srv] accept from {peer}", flush=True)
        while True:
            d = c.recv(64)
            if not d:
                break
            c.sendall(b"pong")
        c.close()


def client(a):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

    if not a.skip_setsockopt:
        val = int(a.val, 0)
        if a.opt in ("tclass", "both"):
            s.setsockopt(socket.IPPROTO_IPV6, IPV6_TCLASS, val)
            print(f"[cli] set IPV6_TCLASS = {val:#04x}", flush=True)
        if a.opt in ("tos", "both"):
            s.setsockopt(socket.IPPROTO_IP, IP_TOS, val)
            print(f"[cli] set IP_TOS      = {val:#04x}", flush=True)

    target = f"::ffff:{a.dst}"
    print(f"[cli] connect {target}:{a.port}  (v4-mapped)", flush=True)
    s.connect((target, a.port))

    # What the kernel actually stored in each field:
    stored_tc  = s.getsockopt(socket.IPPROTO_IPV6, IPV6_TCLASS)
    stored_tos = s.getsockopt(socket.IPPROTO_IP,  IP_TOS)
    print(f"[cli] peer={s.getpeername()[0]}  "
          f"readback IPV6_TCLASS={stored_tc:#04x} IP_TOS={stored_tos:#04x}",
          flush=True)
    print("[cli] ^ wire ToS is driven by IP_TOS (inet->tos) for mapped sockets",
          flush=True)

    for _ in range(a.count):
        s.sendall(b"ping")
        s.recv(64)
        time.sleep(a.interval)
    s.close()


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)

    sp = sub.add_parser("server")
    sp.add_argument("--port", type=int, default=5201)

    cp = sub.add_parser("client")
    cp.add_argument("--dst", default="10.0.0.2")
    cp.add_argument("--port", type=int, default=5201)
    cp.add_argument("--skip-setsockopt", action="store_true")
    cp.add_argument("--opt", choices=["none", "tclass", "tos", "both"], default="tos")
    cp.add_argument("--val", default="0xb8")          # EF, DSCP 46
    cp.add_argument("--count", type=int, default=4)
    cp.add_argument("--interval", type=float, default=0.3)

    a = ap.parse_args()
    (server if a.mode == "server" else client)(a)


if __name__ == "__main__":
    main()
