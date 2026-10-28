#!/bin/bash
# matrix_httpd.sh <tag> [case ...]  -> appends results to results.<tag>
# With no case names, runs the full matrix.
# Example: ./matrix_httpd.sh httpd
#          ./matrix_httpd.sh httpd idle100 1x1
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
TAG=$1
shift
OUT="$DIR/results.$TAG"
touch "$OUT"
WANT=${*:-all}
want() { [ "$WANT" = all ] || [[ " $WANT " == *" $1 "* ]]; }
run() {
  local case=$1
  if want "$case"; then
    echo ""
    echo "========================================================"
    echo "[matrix] STARTING case=$case at $(date)"
    echo "========================================================"
    ./run_httpd.sh "$TAG:$case" "${@:2}" 2>&1 | tee -a "$OUT"
    echo "[matrix] FINISHED case=$case rc=$? at $(date)"
    echo ""
  else
    echo "[matrix] SKIPPING case=$case"
  fi
}

echo "=== httpd H3 benchmark matrix: $TAG  $(date) ===" | tee -a "$OUT"
echo "[matrix] PID=$$  cases=${WANT}"

# idle fleet: N conns, settled, 40 s measurement
run idle100   idle 100   0 1 40 --stagger 0.004 --settle 35 --keepalive 12
run idle1000  idle 1000  0 2 40 --stagger 0.004 --settle 35 --keepalive 12
run idle2000  idle 2000  0 4 40 --stagger 0.004 --settle 35 --keepalive 12
run idle4000  idle 4000  0 4 40 --stagger 0.004 --settle 35 --keepalive 12
run idle8000  idle 8000  0 8 40 --stagger 0.004 --settle 35 --keepalive 12 --ramp-timeout 300

# request load: conns x streams
run 1x1    load 1  1   1 12
run 1x32   load 1  32  1 12
run 1x64   load 1  64  1 12
run 1x100  load 1  100 1 12
run 4x25   load 4  25  4 12
run 8x25   load 8  25  4 12
run 16x16  load 16 16  4 12
run 32x32  load 32 32  8 12

echo "=== done $(date) ===" | tee -a "$OUT"
