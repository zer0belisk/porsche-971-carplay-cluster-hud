#!/bin/sh
set -e
cd "$(dirname "$0")"
IMG=qnx65-armv7-toolchain:8.5
# v74: the phone draws 1200x720, the NvSS scaler shrinks it onto the 800x480 panel.
GEO="-DCLUSTER_W=1200 -DCLUSTER_H=720 -DPANEL_W=800 -DPANEL_H=480"
PHYS="-DCLUSTER_PHYS_W=90 -DCLUSTER_PHYS_H=54"
# safe areas scaled x1.5 with the announced size, or iOS rejects the view area
SAFE="-DFULL_SAFE_X=15 -DFULL_SAFE_Y=15 -DFULL_SAFE_W=1170 -DFULL_SAFE_H=570 \
      -DSS_SAFE_X=15  -DSS_SAFE_Y=15  -DSS_SAFE_W=840  -DSS_SAFE_H=570 \
      -DCL_SAFE_X=180 -DCL_SAFE_Y=15  -DCL_SAFE_W=840  -DCL_SAFE_H=570"
docker run --rm -v "$PWD":/src -w /src $IMG \
  arm-unknown-nto-qnx6.5.0eabi-gcc -marm -shared -fPIC -O2 -Wall \
  $GEO $PHYS $SAFE -o carplay_hook_v74.so carplay_hook_v74.c
