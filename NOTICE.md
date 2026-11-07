# NOTICE

This project is independent reverse-engineering done by the owner on their own
Porsche 971 / PCM 4.1, for interoperability with Apple CarPlay. It ships **no**
Porsche, Harman or Volkswagen-Group firmware, binaries, or decompiled source.

- `hook/carplay_hook.c` references memory offsets and struct layouts that were
  measured from the owner's own head unit. No OEM binary is included.
- `hud/.../ServiceManagerNavi.java` reproduces the method signatures of a stock
  HMI class so that the HMI's class loader accepts it in place of the original
  (class shadowing). It contains no OEM bytecode; the behaviour is a
  reimplementation plus one added call. The stock `hmi.jar` is **not** included
  and is required to compile.

## Prior work this builds on

- **CorsairCat/mhi2-pcm4-carplay-alt-cluster** — Porsche PCM4 altScreen cluster
  video; the architecture reference.
- **luka-dev/mib2q-carplay-rgi** — the Route Guidance reference for MHI2Q.
- **edzenis/mib2high-carplay-altscreen-rgi** — car-tested RGI + HUD for MIB2 High.
- **fifthBro/mh2p-cluster** — PCM5 / MH2P cluster bridge.

Trademarks (Porsche, Apple CarPlay, Harman, Tegra, QNX) belong to their owners.
