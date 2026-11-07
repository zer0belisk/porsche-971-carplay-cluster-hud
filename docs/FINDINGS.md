# Findings

Reverse-engineering notes that cost the most time, so you don't repeat them.

## The grey turn card was ours, not iOS

With a route active, Apple Maps put a full-screen grey turn card
("Continue straight", lane arrows) on the cluster instead of the map. It was
**not** an iOS limitation. Two of our own choices caused it, together:

1. The cluster was advertised with `initialURL = maps:/car/instrumentcluster`
   (root = *anyContent*, itemType 3). iOS reads `/info` once per session and
   creates the cluster window for that content type.
2. After the stream started, the hook answered the phone's `suggestUI` with OK
   and sent its own `showUI` burst, which flipped the window to the card ~1 s
   after the map appeared.

Fix: `initialURL` = the **map-only** scene, and do **not** answer `suggestUI` or
send `showUI` (stock answers `suggestUI` with `-6714`). Then the map holds.

> A `status=0` acknowledgement from the phone for a scene command does **not**
> mean it took visual effect. Decode a cluster frame (`tools/pcm/cluster_frame.sh`)
> and look, rather than trusting return codes.

## Liveness by connection, not frame timing

Apple Maps only sends a cluster frame when its picture changes. A static map (or
a static card) sends nothing. A naive "no decoded frame for 3 s ⇒ stream dead"
watchdog therefore killed the cluster on every quiet moment. Judge the stream
alive from the 111 connection and from real access units (op 0) only — config
packets (op 1) and housekeeping (op 5) are not frames.

## libKD has no refcount (the teardown crash)

Leaving CarPlay for another menu used to crash `dio_manager` at a fixed address
in `libKD`. Cause: `kdTerminateNV` frees libKD's process-global state with **no
reference count**. With a second NvSS stream alive (ours), the first teardown
frees libKD for the whole process and the survivor faults on its next
`kdThreadCreate`. Both consumers import `kdInitializeNV`/`kdTerminateNV` by
name, so the missing refcount can be supplied from the `LD_PRELOAD` hook — no
`libKD` patch. Stock never hits it because stock opens exactly one stream.

## Decoder bandwidth

One Tegra 3 hardware decoder carries both the main screen (1328×480) and the
cluster. 1200×720 @ 30 fps for the cluster is fine alongside the main screen;
1440×864 @ 30 fps starts to starve it. If the main screen stutters, drop the
cluster to 20 fps (`echo 20 > /tmp/alt_fps`) — barely visible on a map.

## Apple Maps' cluster zoom command is ignored here

`changeMapZoomLevel{uuid,zoomDirection}` is accepted (`status=0`) but does not
change the cluster zoom on this unit, route or not. Cluster zoom is only
controllable by the announced stream resolution (how many pixels the phone
draws before the scaler shrinks them onto the panel).

## HUD arrow: distance is in tenths, and sync must be complete

`BAPDistanceFormatter` carries distances as `round(value*10)` — send `3000` to
show "300 ft". And the arrow stays hidden until the 20 s incomplete-sync timeout
unless the full BAP function set is sent on guidance start (17,39,23,18,49).
Sending only a subset is what made the first arrow appear ~40 s late.

## Parking-sensor / CarPlay-won't-reopen (open)

Stock `HighPriorityResourceTracker.processMsg(108)` blocks the CarPlay screen
while the parking (OPS) or reverse-camera screen is up, and only `107` unblocks
it. If a trailing `108` arrives without a matching `107`, the block sticks: the
CarPlay icon is there but the screen never returns until a PCM reset. This is the
same issue fixed upstream in chefranov/mhi2-au37x-carplay#42 by not blocking on
an OPS-only `108`. Not yet implemented here.
