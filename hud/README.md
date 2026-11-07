# HUD arrow bridge

Shadows the stock `de.audi.app.combi.bap.app.navi.ServiceManagerNavi` so the HMI
loads our class instead (the HMI start script prepends `lsd/jars/*.jar` to the
bootclasspath). Our version is byte-for-byte the stock logic plus one call that
hands the live `AppConnectorNavi` to `de.carplay.hud.HudBridge`.

`HudBridge` polls `/tmp/hud_cmd` (one command per line) and calls the stock
`CombiBAPServiceNavi`, which drives the factory arrow on the HUD and cluster.

## Commands

```
TURN <mainElement> <direction> <distance> <unit> [street...]   new maneuver
DIST <distance> <unit>                                         countdown only
STOP                                                           clear / route end
RGTYPE <n>                                                     ActiveRGType (default 4)
```

- `unit`: `ft`, `mi`, `km`, `m` (or a raw BAP unit code). Distance in plain form
  (`300`, `0.5`); the bridge multiplies by 10 (BAP carries tenths).
- `mainElement` / `direction` are the BAP codes from `CombiBAPConstantsNavi`
  (MU1416): e.g. `FOLLOW_STREET=11`, `TURN=13`, `EXIT_RIGHT=15`, `UTURN=25`,
  `ROUNDABOUT_TRS_RIGHT=21`, `ARRIVED=3`; direction `0`=straight, `64`=left,
  `192`=right, `32/224`=slight, `96/160`=sharp, `128`=u-turn.

## Safety

- Anything shown auto-clears after 60 s with no new command.
- `/tmp/hud_bridge_off` present → the bridge does nothing and clears.
- Every call is guarded; a failure in the bridge never reaches stock navigation.
- Log: `/tmp/hud_bridge.log`.

## Build

`sh build_hud_jar.sh` — JDK 8 in Docker, `-source/-target 1.4`, compiled against
the stock `hmi.jar` (which you must supply; it is **not** in this repo).
