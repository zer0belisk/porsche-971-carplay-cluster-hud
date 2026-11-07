#!/bin/sh
# M.I.B. custom-script entry point.
# Copy the whole install/ folder onto the M.I.B. SD card as /mod/, then run
#   Main -> M.I.B. -> Advanced Settings -> Run Custom Script
# which executes /mod/custom.sh. This locates install.sh and runs it.
SD=/net/mmx/fs/sda0
for base in "$SD/mod" "$SD/mod/install" "$(dirname "$0")" "$(dirname "$0")/.." ; do
    if [ -f "$base/install.sh" ]; then
        echo "running $base/install.sh"
        sh "$base/install.sh"
        echo "--- finished. Reboot the PCM. ---"
        exit 0
    fi
done
echo "install.sh not found next to custom.sh — copy install/ to the SD /mod/"
exit 1
