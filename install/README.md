# Install

## Requirements

- Porsche 971 / PCM 4.1 on firmware **MHI2_US_POG24 / MU1416** (the installer
  refuses other builds — see the firmware guard in `install.sh`).
- A working **M.I.B. (More Incredible Bash)** SD card for your unit, or any root
  shell on the PCM.
- The QNX 6.5 ARMv7 toolchain is **not** needed to install — prebuilt
  `carplay_probe.so` and `carplay_hud.jar` ship in `payload/`. It is only needed
  to rebuild from source (`hook/build.sh`, `hud/build_hud_jar.sh`).

## Via M.I.B. (recommended)

1. Copy this whole `install/` folder onto the M.I.B. SD card so that the card
   has `/mod/custom.sh`, `/mod/install.sh` and `/mod/payload/`.
   (i.e. put the contents of `install/` into the SD's `mod/` directory, and move
   `mib/custom.sh` to `mod/custom.sh`.)
2. In the car: **Main → M.I.B. → Advanced Settings → Run Custom Script**.
3. Reboot the PCM when it finishes (hold the volume knob ~15 s).

## Via SSH (manual)

With the iPhone unplugged, copy `install/` to the unit and run as root:

```sh
sh install.sh        # refuses unless firmware is MU1416; FORCE=1 to override
# ... reboot the PCM ...
```

## Verify

Plug the phone, open CarPlay: the map appears on the right cluster screen. Start
a route in Apple Maps: the cluster keeps the map and the factory turn arrow
appears on the HUD (the arrow needs a route-guidance feeder — see the repo
README; without it you can still test with `echo "TURN 13 192 300 ft Main St" >
/tmp/hud_cmd`).

## Kill switch / uninstall

- Disable without a laptop: `echo 0 > /tmp/hook_level` (and reboot clears `/tmp`).
- Full removal: `sh uninstall.sh` then reboot.
