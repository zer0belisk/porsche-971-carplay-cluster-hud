#!/bin/sh
# Fetch the cluster stream dump from the unit and decode its LAST frame to PNG.
#   tools/pcm/cluster_frame.sh <out.png>
set -e
D="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d)
expect "$D/pcmget.exp" "$HOME/.pcmpw" /tmp/cluster.h264 "$T/c.h264" >/dev/null 2>&1
ffmpeg -hide_banner -loglevel error -f h264 -i "$T/c.h264" -vf "select='eq(n\,0)+1'" -fps_mode vfr "$T/f%04d.png" 2>/dev/null || true
last=$(ls "$T"/f*.png 2>/dev/null | tail -1)
[ -n "$last" ] && cp "$last" "$1" && echo "$(ls "$T"/f*.png | wc -l | tr -d ' ') frames, last -> $1"
rm -rf "$T"
