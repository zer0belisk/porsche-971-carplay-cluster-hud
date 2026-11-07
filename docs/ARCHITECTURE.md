# Architecture

## Hardware / firmware

| | |
|---|---|
| Car | Porsche Panamera 971, PCM 4.1 (Harman MHI2 High) |
| SoC | NVIDIA Tegra 3 (T30), ARMv7, QNX 6.5 |
| Firmware | `MHI2_US_POG24`, build MU1416, HW 055 |
| Cluster | right 7" LVDS screen, DisplayManager display id 4, 800×480 |
| Transport | wired USB, iAP2, IPv6 on `carplay0` |

## Cluster map (dio_manager hook)

`carplay_hook.c` is an `LD_PRELOAD` library loaded into `dio_manager` via the
env block of `/etc/eso/production/smartphone_integrator.json`.

1. **Advertise a second display.** Rewrites the control-SETUP response to add
   `altScreen` + `viewAreas` to `enabledFeatures`, and injects a second display
   dict into the `/info` response (`displays`, `displayPanels`,
   `extendedFeatures`, `altScreenSuggestUIURLs`). The cluster display is type
   **111** (instrument cluster), 800×480, with its own uuid.
2. **Pin the scene.** The display's `initialURL` is the **map-only** scene
   (`maps:/car/instrumentcluster/map?showETA=no&maneuverLayout=no&showSpeedLimit=no`).
   The hook does **not** answer the phone's `suggestUI` (stock answers it with
   `-6714`); answering it, or re-sending `showUI`, flips the cluster to a
   full-screen turn card during guidance. This is the single most important
   cluster setting — see FINDINGS.
3. **Receive + decode.** iOS offers stream 111; the hook opens a listener on a
   pf-permitted port, answers with a real dataPort, receives the H.264, AES-CTR
   decrypts it, converts avcC/AVCC to Annex-B, and feeds a second
   `dio::NvssVideoImpl` (exported by `libairplay.so`) aimed at the cluster
   output device / layer.
4. **Composite.** Points DisplayManager display 4 at the stock context that
   already contains the cluster layer, so no new HMI context is needed for the
   picture. On disconnect / stall the cluster returns to the stock Porsche map.

Geometry: the phone is asked to draw 1200×720 and the NvSS scaler shrinks it
onto the 800×480 panel (more map in frame than a 1:1 800×480 stream). 30 fps.

## HUD arrows (HMI shadow class)

`ServiceManagerNavi.java` replaces the stock class of the same name (class
shadowing via `lsd/jars` on the bootclasspath). It keeps the stock behaviour and
adds one call that passes the live `AppConnectorNavi` (the stock
`CombiBAPServiceNavi` implementation) to `HudBridge`.

`HudBridge` reads `/tmp/hud_cmd` and calls the stock service:

```
updateRGStatus(1)                        FctID 17  guidance active
updateActiveRGType(4)                    FctID 39  cluster-with-map RG type
updateManeuverDescriptor([{main,dir,…}]) FctID 23  the arrow
updateDistanceToNextManeuver(d,unit,…)   FctID 18  distance (tenths)
updateExitView(1,0)                      FctID 49  no exit view (NAR)
updateTurnToInfo(street,"")              FctID 20  street name
```

BAP function synchronisation (`FunctionSynchronizationNavi`) waits for the full
set {17,39,23,18,49} on guidance start and {23,18,49} on each maneuver change;
sending the complete set makes the arrow appear immediately instead of after the
20 s incomplete-sync timeout.

The **input** half — reading iAP2 Route Guidance (0x5201/0x5202/0x5204) from the
phone and writing `TURN`/`DIST`/`STOP` — runs in `mm-ipod` and is out of scope
for this repository; the bridge interface is documented so any feeder can drive
it.
