#!/bin/bash
# run_tomcat.sh <tag> <mode> <conns> <streams> <procs> <duration> [extra...]
# Adapted from run_httpd.sh for Tomcat (single-process, multi-threaded).
set -u
ulimit -n 65536
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
TAG=$1 MODE=$2 CONNS=$3 STREAMS=$4 PROCS=$5 DUR=$6
shift 6
echo "[run_tomcat] START tag=$TAG mode=$MODE conns=$CONNS streams=$STREAMS procs=$PROCS dur=$DUR extras='$*'"
PID=$(pgrep -f 'org.apache.catalina.startup.Bootstrap' | head -1)
[ -z "$PID" ] && PID=$(pgrep -f '[Cc]atalina' | head -1)
[ -z "$PID" ] && { echo "[run_tomcat] ERROR: Tomcat not running"; exit 1; }
echo "[run_tomcat] Tomcat PID=$PID"
PORT=$(ss -ulnp | grep "pid=$PID" | grep -oP '\*:(\d+)' | head -1 | cut -d: -f2)
[ -z "$PORT" ] && { echo "[run_tomcat] ERROR: cannot find Tomcat UDP/QUIC port"; exit 1; }
echo "[run_tomcat] detected QUIC port=$PORT"
rm -f out.$TAG.*.json
PER=$(( (CONNS + PROCS - 1) / PROCS ))

# Compute a generous timeout: settle/warmup + duration + ramp + margin
if [ "$MODE" = "idle" ]; then
  TIMEOUT=$(( DUR + 35 + 180 + 30 ))
else
  TIMEOUT=$(( DUR + 3 + 180 + 30 ))
fi
echo "[run_tomcat] per-shard timeout=${TIMEOUT}s"

pids=()
for i in $(seq 0 $((PROCS-1))); do
  n=$PER; rem=$(( CONNS - i*PER ))
  [ $rem -lt $n ] && n=$rem
  [ $n -le 0 ] && break
  sp=0
  [ $i -eq 0 ] && sp=$PID
  echo "[run_tomcat] launching shard $i: $n conns, server-pid=$sp"
  timeout --signal=TERM "$TIMEOUT" \
    python3 bench.py --mode "$MODE" --port $PORT --connections $n --streams $STREAMS \
      --duration $DUR --warmup 3 --settle 15 --hold "$DUR" \
      --ramp-timeout 180 --server-pid $sp \
      --out out.$TAG.$i.json "$@" &
  pids+=($!)
  echo "[run_tomcat] shard $i pid=${pids[-1]}"
done

echo "[run_tomcat] waiting for ${#pids[@]} shard(s): ${pids[*]}"

heartbeat() {
  local elapsed=0
  while true; do
    sleep 10
    elapsed=$((elapsed + 10))
    echo "[run_tomcat] ... still running (${elapsed}s elapsed)"
  done
}
heartbeat &
HB_PID=$!

fail=0
for idx in "${!pids[@]}"; do
  p=${pids[$idx]}
  wait "$p"
  rc=$?
  if [ $rc -eq 124 ]; then
    echo "[run_tomcat] shard $idx (pid $p) TIMED OUT after ${TIMEOUT}s"
    fail=1
  elif [ $rc -ne 0 ]; then
    echo "[run_tomcat] shard $idx (pid $p) exited rc=$rc"
    fail=1
  else
    echo "[run_tomcat] shard $idx (pid $p) OK"
  fi
done

kill $HB_PID 2>/dev/null
wait $HB_PID 2>/dev/null

[ $fail -ne 0 ] && echo "[run_tomcat] WARNING: case $TAG had shard failures"
echo "[run_tomcat] merging out.$TAG.*.json"
ls -la out.$TAG.*.json 2>/dev/null || echo "[run_tomcat] WARNING: no output files found"
printf '%-28s ' "$TAG"
python3 merge.py "out.$TAG.*.json"
echo "[run_tomcat] DONE tag=$TAG"
