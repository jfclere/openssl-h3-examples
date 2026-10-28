#!/usr/bin/env python3
"""aioquic-based HTTP/3 load/idle harness for the Tomcat QUIC endpoints.

Modes:
  load  N connections x S concurrent stream workers, each worker sends
        sequential pipelined GETs for --duration seconds.
  idle  N connections, one bootstrap GET each, then hold (aioquic PING
        keeps them alive); used with an external poller-CPU sampler.

Each process writes a JSON shard to --out; run merge.py to aggregate.
"""
import argparse
import asyncio
import json
import ssl
import time

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamReset


class LoadProto(QuicConnectionProtocol):
    def __init__(self, quic, stream_handler=None, authority=b"localhost"):
        super().__init__(quic, stream_handler)
        self.h3 = H3Connection(quic)
        self._authority = authority
        self._pending = {}
        self.alive = True

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self.alive = False
            for fut, _ in self._pending.values():
                if not fut.done():
                    fut.set_exception(ConnectionError("terminated"))
            return
        if isinstance(event, StreamReset):
            entry = self._pending.pop(event.stream_id, None)
            if entry and not entry[0].done():
                entry[0].set_exception(ConnectionError("reset"))
            return
        for ev in self.h3.handle_event(event):
            if not getattr(ev, "stream_ended", False):
                continue
            entry = self._pending.pop(ev.stream_id, None)
            if entry and not entry[0].done():
                entry[0].set_result(entry[1])

    def get(self, path):
        stream_id = self._quic.get_next_available_stream_id()
        fut = asyncio.get_running_loop().create_future()
        t0 = time.perf_counter()
        self._pending[stream_id] = (fut, t0)
        self.h3.send_headers(
            stream_id=stream_id, end_stream=True,
            headers=[
                (b":method", b"GET"), (b":scheme", b"https"),
                (b":authority", self._authority),
                (b":path", path.encode("ascii")),
            ])
        self.transmit()
        return fut


def make_config():
    cfg = QuicConfiguration(is_client=True)
    cfg.alpn_protocols = ["h3"]
    cfg.verify_mode = ssl.CERT_NONE
    cfg.max_idle_timeout = 30000
    return cfg


class Stats:
    def __init__(self):
        self.n = 0
        self.wn = 0
        self.lats = []
        self.err = 0
        self.conns = 0
        self.ready = asyncio.Event()


async def worker(proto, st, stop, window, path):
    while not stop.is_set() and proto.alive:
        try:
            fut = proto.get(path)
        except Exception:
            break
        try:
            t0 = await fut
        except Exception:
            st.err += 1
            break
        st.n += 1
        now = time.perf_counter()
        if now >= window[0]:
            st.wn += 1
            st.lats.append(now - t0)


async def conn_task(args, st, stop, window, i):
    if args.stagger:
        await asyncio.sleep(i * args.stagger)
    while not stop.is_set():
        try:
            async with connect(args.host, args.port,
                               configuration=make_config(),
                               create_protocol=LoadProto) as client:
                st.conns += 1
                if args.bootstrap_get:
                    try:
                        await asyncio.wait_for(client.get(args.path), 10)
                    except Exception:
                        st.err += 1
                st.n_conns_ready = getattr(st, "n_conns_ready", 0) + 1
                if st.n_conns_ready >= args.connections:
                    st.ready.set()
                workers = [asyncio.create_task(
                    worker(client, st, stop, window, args.path))
                    for _ in range(args.streams)]
                if args.keepalive and args.streams == 0:
                    while not stop.is_set():
                        await asyncio.sleep(args.keepalive)
                        try:
                            await client.ping()
                            client.transmit()
                        except Exception:
                            break
                else:
                    await stop.wait()
                for w in workers:
                    w.cancel()
                return
        except Exception:
            st.err += 1
            await asyncio.sleep(0.5)


def read_ticks(pid, tid=None):
    p = "self" if pid is None else pid
    if not tid or tid == "0":
        path = f"/proc/{p}/stat"
        with open(path) as f:
            fields = f.read().rsplit(") ", 1)[1].split()
        return int(fields[11]) + int(fields[12])  # utime + stime
    total = 0
    for one in str(tid).split(","):
        one = one.strip()
        if not one:
            continue
        with open(f"/proc/{p}/task/{one}/stat") as f:
            fields = f.read().rsplit(") ", 1)[1].split()
        total += int(fields[11]) + int(fields[12])
    return total


def read_ticks_tree(pid):
    """Read utime+stime for pid and all its children via /proc/*/stat."""
    import os
    total = read_ticks(pid)
    try:
        children_data = open(f"/proc/{pid}/task/{pid}/children").read().split()
    except FileNotFoundError:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/stat") as f:
                    fields = f.read().rsplit(") ", 1)[1].split()
                if int(fields[1]) == int(pid):  # ppid
                    total += int(fields[11]) + int(fields[12])
            except (FileNotFoundError, ProcessLookupError, IndexError):
                continue
        return total
    for cpid in children_data:
        total += read_ticks(int(cpid))
    return total


async def run(args):
    st = Stats()
    stop = asyncio.Event()
    window = [0.0]
    tasks = [asyncio.create_task(conn_task(args, st, stop, window, i))
             for i in range(args.connections)]
    try:
        await asyncio.wait_for(st.ready.wait(), args.ramp_timeout)
    except TimeoutError:
        pass  # ramp errors counted; measure with what connected
    await asyncio.sleep(args.warmup)
    snap0 = {}
    if args.server_pid:
        snap0 = {"poller": read_ticks(args.server_pid, args.poller_tid),
                 "server": read_ticks_tree(args.server_pid),
                 "client": read_ticks(None)}
    t0 = time.perf_counter()
    window[0] = t0
    await asyncio.sleep(args.duration)
    el = time.perf_counter() - t0
    if args.server_pid:
        snap1 = {"poller": read_ticks(args.server_pid, args.poller_tid),
                 "server": read_ticks_tree(args.server_pid),
                 "client": read_ticks(None)}
        cpu = {k: (snap1[k] - snap0[k]) * 100.0 / 100 / el
               for k in snap1}
    else:
        cpu = {}
    stop.set()
    await asyncio.gather(*tasks, return_exceptions=True)
    out = {
        "conns": st.conns, "reqs": st.n, "win_reqs": st.wn,
        "errs": st.err, "lats": st.lats, "window_s": el, "cpu": cpu,
    }
    with open(args.out, "w") as f:
        json.dump(out, f)
    print(json.dumps({k: out[k] for k in
                      ("conns", "reqs", "win_reqs", "errs")}))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["load", "idle"], default="load")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8444)
    p.add_argument("--path", default="/h3test.html")
    p.add_argument("--connections", type=int, default=1)
    p.add_argument("--streams", type=int, default=1)
    p.add_argument("--duration", type=float, default=10)
    p.add_argument("--warmup", type=float, default=2)
    p.add_argument("--hold", type=float, default=40)
    p.add_argument("--settle", type=float, default=20)
    p.add_argument("--ramp-timeout", type=float, default=120)
    p.add_argument("--bootstrap-get", action="store_true")
    p.add_argument("--out", default="/tmp/h3bench/out.json")
    p.add_argument("--stagger", type=float, default=0.0)
    p.add_argument("--keepalive", type=float, default=0.0)
    p.add_argument("--server-pid", type=int, default=0)
    p.add_argument("--poller-tid", type=str, default="0")
    args = p.parse_args()
    if args.mode == "idle":
        args.streams = 0
        args.bootstrap_get = True
        args.warmup = args.settle
        args.duration = args.hold
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
