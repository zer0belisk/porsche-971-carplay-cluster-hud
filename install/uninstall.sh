#!/bin/sh
# Remove the CarPlay cluster map + HUD-arrow bridge. Run ON THE PCM as root,
# iPhone UNPLUGGED. Reboot the PCM afterwards.
set -e
CFG=/etc/eso/production/smartphone_integrator.json

if pidin ar 2>/dev/null | grep -q "[d]io_manager"; then
    echo "dio_manager is running — unplug the phone and retry"; exit 1
fi

echo 0 > /tmp/hook_level 2>/dev/null || true

echo "removing library, jar and level files"
mount -uw /mnt/app
rm -f /mnt/app/eso/lib/carplay_probe.so
rm -f /mnt/app/eso/hmi/lsd/jars/carplay_hud.jar
rm -f /mnt/app/eso/lib/hook_level /mnt/app/eso/lib/alt_fps
mount -ur /mnt/app
sync

echo "restoring $CFG"
mount -uw /mnt/system
if [ -f "$CFG.ORIG" ]; then
    cp "$CFG.ORIG" "$CFG"
    rm -f "$CFG.ORIG"
else
    # no backup: just strip our LD_PRELOAD line
    sed -i 's#"LD_PRELOAD=/eso/lib/carplay_probe.so", ##' "$CFG"
fi
mount -ur /mnt/system
sync

echo "done. REBOOT the PCM once. The unit is back to stock."
