#!/bin/sh
# Build carplay_hud.jar for the MU1416 J9 (Foundation 1.1): JDK 8, -source/-target 1.4,
# compiled against the stock HMI classes in hmi.jar. No AppleDouble files in the jar.
set -e
cd "$(dirname "$0")/.."
rm -rf hud/build && mkdir -p hud/build/classes
docker run --rm -v "$PWD":/w -w /w eclipse-temurin:8-jdk sh -c '
  javac -nowarn -source 1.4 -target 1.4 -encoding UTF-8 \
        -cp hmi.jar -d hud/build/classes \
        hud/java/src/de/audi/app/combi/bap/app/navi/ServiceManagerNavi.java \
        hud/java/src/de/carplay/hud/HudBridge.java \
        hud/java/src/de/carplay/hud/RgiReceiver.java \
        hud/java/src/de/carplay/hud/ManeuverMap.java &&
  cd hud/build/classes && jar cf ../carplay_hud.jar de'
find hud/build -name '._*' -delete
unzip -l hud/build/carplay_hud.jar
