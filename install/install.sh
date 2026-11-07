#!/bin/sh
# Install the CarPlay cluster map + HUD-arrow bridge on a Porsche 971 / PCM 4.1.
#
# Run ON THE PCM as root, with the iPhone UNPLUGGED. Reversible, file-level:
# - copies carplay_probe.so into /mnt/app/eso/lib and adds one LD_PRELOAD line
#   to dio_manager's env block (backed up as .ORIG),
# - copies carplay_hud.jar into /mnt/app/eso/hmi/lsd/jars,
# - writes persistent level files.
# A PCM reboot is required once (both the env block and the HMI jar list are
# cached at boot).
#
# FIRMWARE GUARD: refuses unless the unit reports train POG24 + build MU1416.
# Override only if you have verified your firmware yourself: FORCE=1 sh install.sh
set -e

LIB_DST=/mnt/app/eso/lib/carplay_probe.so
JAR_DST=/mnt/app/eso/hmi/lsd/jars/carplay_hud.jar
CFG=/etc/eso/production/smartphone_integrator.json
PRELOAD='"LD_PRELOAD=/eso/lib/carplay_probe.so", '

SRC="$(cd "$(dirname "$0")/payload" && pwd)"
[ -f "$SRC/carplay_probe.so" ] || { echo "missing payload/carplay_probe.so"; exit 1; }
[ -f "$SRC/carplay_hud.jar"  ] || { echo "missing payload/carplay_hud.jar";  exit 1; }

# --- firmware guard ---------------------------------------------------------
if [ "${FORCE:-0}" != "1" ]; then
    hit=0
    for f in /mnt/app/metainfo2.txt /mnt/app/swdl/metainfo2.txt \
             /mnt/system/etc/version /mnt/app/etc/version \
             /mnt/app/eso/hmi/lsd/version.txt ; do
        [ -f "$f" ] || continue
        if grep -q "POG24" "$f" 2>/dev/null && grep -q "MU1416" "$f" 2>/dev/null; then
            hit=1; echo "firmware OK: POG24 / MU1416 ($f)"; break
        fi
    done
    if [ "$hit" != "1" ]; then
        echo "REFUSING: could not confirm this is MHI2_US_POG24 / MU1416."
        echo "This build was made for exactly that firmware; other trains have"
        echo "different offsets and this can break CarPlay. If you are certain"
        echo "your firmware matches, re-run with:  FORCE=1 sh install.sh"
        exit 2
    fi
fi

# --- do not install over a running dio_manager ------------------------------
if pidin ar 2>/dev/null | grep -q "[d]io_manager"; then
    echo "dio_manager is running — unplug the phone and retry"; exit 1
fi

echo "mounting /mnt/app read-write"
mount -uw /mnt/app

echo "installing cluster hook library"
cp "$SRC/carplay_probe.so" "$LIB_DST"
chmod 755 "$LIB_DST"

echo "installing HUD bridge jar"
cp "$SRC/carplay_hud.jar" "$JAR_DST"
chmod 644 "$JAR_DST"

# persistent feature level (survives reboot): 7 = cluster map on, 30 fps
echo 7  > /mnt/app/eso/lib/hook_level
echo 30 > /mnt/app/eso/lib/alt_fps

echo "mounting /mnt/app read-only"
mount -ur /mnt/app
sync

# --- LD_PRELOAD line in the dio_manager env block ---------------------------
if grep -q "carplay_probe.so" "$CFG"; then
    echo "LD_PRELOAD already present in $CFG"
else
    echo "adding LD_PRELOAD to the dio_manager env block"
    mount -uw /mnt/system
    [ -f "$CFG.ORIG" ] || cp "$CFG" "$CFG.ORIG"
    sed -i "s#\"IPL_CONFIG_DIR_DIO_MANAGER=/etc/eso/production\"#${PRELOAD}\"IPL_CONFIG_DIR_DIO_MANAGER=/etc/eso/production\"#" "$CFG"
    mount -ur /mnt/system
    sync
fi

echo
echo "done. REBOOT the PCM once (hold the volume knob ~15 s)."
echo "After reboot: plug the phone, open CarPlay — the cluster map appears,"
echo "and with an Apple Maps route the factory arrow shows on the HUD."
echo
echo "kill switch without a laptop:  echo 0 > /tmp/hook_level"
echo "full removal:                  sh uninstall.sh ; reboot"
