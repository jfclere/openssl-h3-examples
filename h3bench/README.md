# h3bench — HTTP/3 QUIC scalability harness

An aioquic-based benchmark for measuring HTTP/3 server performance over QUIC.
Originally written for Apache Tomcat's QUIC endpoints, adapted here for Apache httpd.

## What it measures

- **Request throughput** (RPS) at various connection x stream concurrency shapes
- **Latency** (p50, p99)
- **Server CPU** (total across all server processes, via `/proc/*/stat`)
- **Idle fleet cost** — CPU consumed just holding open connections with no traffic

## Prerequisites

- Python 3 with `aioquic` installed (`pip install aioquic`)
- An HTTP/3 server listening on a UDP port (auto-detected for httpd)
- A 70-byte static file at `/h3test.html` on the server (copy `h3test.html` to the document root)
- Linux (uses `/proc` for CPU measurement)

## Files

| File | Purpose |
|------|---------|
| `bench.py` | Core benchmark client. Opens QUIC connections, sends GETs, records latency and CPU. |
| `merge.py` | Aggregates JSON shards from parallel bench.py processes into a single result line. |
| `run_httpd.sh` | Runs a single benchmark case against httpd. Auto-detects PID and UDP port. |
| `matrix_httpd.sh` | Runs the full test matrix (idle fleet + request load) against httpd. |
| `run_case.sh` | Same as run_httpd.sh but for Tomcat (finds JVM PID and poller thread). |
| `matrix.sh` | Full test matrix for Tomcat. |
| `h3test.html` | 70-byte static file to serve as the benchmark target. |

## Quick start (httpd)

```bash
# 1. Copy the target file to httpd's document root
cp h3test.html /path/to/htdocs/

# 2. Run the full matrix
./matrix_httpd.sh httpd

# 3. Or run a single case (e.g. 8 connections, 25 streams each, 12s duration)
./run_httpd.sh mytag load 8 25 4 12
```

Results are appended to `results.<tag>` and individual JSON shards are written as `out.<tag>.<shard>.json`.

## bench.py usage

```
python3 bench.py [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--mode` | `load` | `load` = throughput test; `idle` = hold connections open |
| `--host` | `127.0.0.1` | Server address |
| `--port` | `8444` | QUIC/UDP port |
| `--path` | `/h3test.html` | URI to GET |
| `--connections` | `1` | Number of QUIC connections |
| `--streams` | `1` | Concurrent stream workers per connection |
| `--duration` | `10` | Measurement window (seconds) |
| `--warmup` | `2` | Seconds before measurement starts |
| `--server-pid` | `0` | Server PID for CPU sampling (0 = disabled) |
| `--out` | `/tmp/h3bench/out.json` | Output JSON file |
| `--stagger` | `0.0` | Delay between connection starts (seconds) |
| `--keepalive` | `0.0` | PING interval for idle mode (seconds) |

## run_httpd.sh usage

```
./run_httpd.sh <tag> <mode> <conns> <streams> <procs> <duration> [extra bench.py args...]
```

- `tag` — label for output files
- `mode` — `load` or `idle`
- `conns` — total connections (split across procs)
- `streams` — concurrent streams per connection
- `procs` — number of parallel bench.py processes
- `duration` — measurement window in seconds

The script auto-detects the httpd parent PID and the QUIC UDP port.

## Test matrix

The default matrix in `matrix_httpd.sh` mirrors the Tomcat scalability review:

**Idle fleet** (connections held open, no requests):
100, 1000, 2000, 4000, 8000 connections

**Request load** (concurrent GETs):
1x1, 1x32, 1x64, 1x100, 4x25, 8x25, 16x16, 32x32 (connections x streams)
