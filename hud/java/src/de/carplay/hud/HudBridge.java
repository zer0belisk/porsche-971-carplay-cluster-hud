package de.carplay.hud;

import de.audi.atip.interapp.combi.bap.navi.data.CombiBAPNaviManeuverDescriptor;
import de.audi.atip.interapp.combi.bap.navi.CombiBAPServiceNavi;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.Hashtable;

/*
 * Feeds maneuver data into the stock Porsche navigation BAP service, so the
 * cluster and the HUD draw their own OEM arrows - nothing is rendered here.
 *
 * Stage 1: an output test only. Commands come from a file, one line:
 *
 *   TURN <mainElement> <direction> <distance> <unit> [street ...]
 *       e.g.  TURN 13 192 300 ft Test St    (turn right in 300 ft)
 *             TURN 13 64 0.5 mi Main St     (turn left in 0.5 mi)
 *   DIST <distance> <unit>   countdown only, e.g. DIST 250 ft
 *   RGTYPE <n>     ActiveRGType used when guidance starts/stops (default 4)
 *   STOP           clear the arrow and set route guidance inactive
 *
 *   echo "TURN 13 192 300 3 Test St" > /tmp/hud_cmd
 *
 * Codes from CombiBAPConstantsNavi (MU1416): MAIN_ELEMENT_TURN = 13,
 * MAIN_ELEMENT_FOLLOW_STREET = 11; direction 0 straight, 64 left, 192 right,
 * 224 slight right; unit 3 = feet, 4 = miles, 1 = km.
 *
 * Safety:
 *   - anything shown is cleared automatically after TTL_MS, so a test arrow
 *     can never stay on the HUD into a drive;
 *   - /tmp/hud_bridge_off present = the bridge does nothing (and clears);
 *   - every call is guarded; a failure here is logged and never propagates.
 *
 * Java 1.4 / J9 Foundation: no generics, no StringBuilder, no String.format.
 */
public final class HudBridge implements Runnable {
    private static final String CMD_FILE = "/tmp/hud_cmd";
    private static final String OFF_FILE = "/tmp/hud_bridge_off";
    private static final String LOG_FILE = "/tmp/hud_bridge.log";
    private static final long TTL_MS = 60000L;
    private static final long POLL_MS = 500L;

    private static HudBridge instance;

    private static final int EXITVIEW_VARIANT_NAR = 1;

    private final CombiBAPServiceNavi navi;
    private long shownAt;
    private boolean active;
    private int rgType = 4;

    /* CarPlay route guidance state (RgiReceiver) */
    private static final long ARRIVED_SHOW_MS = 15000L;
    private static final long DIST_MIN_MS = 1000L;
    private boolean rgiLink;
    private boolean rgiOwns;
    private String lastKey;
    private int lastTenths = -1;
    private int lastUnit = -1;
    private long lastDistAt;
    private long arrivedAt;
    private long upSince;                 /* when the distance first rose above the shown value */

    /* GPS jitter filter (parked or slow, the phone's distance wobbles 3..25 m):
     * a drop is shown at once; a small rise is noise and ignored; a large rise
     * (turned around, reroute) is shown only if it persists. */
    private static final long DIST_UP_HOLD_MS = 3000L;
    private static final int DIST_UP_MIN_M = 30;

    private HudBridge(CombiBAPServiceNavi navi) {
        this.navi = navi;
    }

    public static synchronized void start(Object service) {
        if (instance != null) {
            log("start: already running");
            return;
        }
        if (!(service instanceof CombiBAPServiceNavi)) {
            log("start: not a CombiBAPServiceNavi: " + (service == null ? "null" : service.getClass().getName()));
            return;
        }
        instance = new HudBridge((CombiBAPServiceNavi) service);
        Thread t = new Thread(instance, "CarPlayHudBridge");
        t.setDaemon(true);
        t.setPriority(Thread.MIN_PRIORITY);
        t.start();
        RgiReceiver.start(instance);
        log("start: bridge up, service=" + service.getClass().getName());
    }

    public void run() {
        while (true) {
            try {
                Thread.sleep(POLL_MS);
                if (new File(OFF_FILE).exists()) {
                    synchronized (this) {
                        if (shownAt != 0) clear("kill switch");
                        rgiOwns = false;
                        lastKey = null;
                    }
                    continue;
                }
                File f = new File(CMD_FILE);
                if (f.exists()) {
                    String line = readFirstLine(f);
                    f.delete();
                    if (line != null) handle(line.trim());
                }
                tick();
            } catch (Throwable t) {
                log("loop error: " + t);
            }
        }
    }

    /* ---- timers: TTL and arrival ------------------------------------- */

    private synchronized void tick() {
        long now = System.currentTimeMillis();
        if (arrivedAt != 0 && now - arrivedAt > ARRIVED_SHOW_MS) {
            clear("arrived");
            arrivedAt = 0;
            rgiOwns = false;
            lastKey = null;
            return;
        }
        /* While the phone link is up the route can be static for minutes
         * (waiting at a light): no TTL then. Link loss clears explicitly. */
        if (rgiOwns && rgiLink) return;
        if (shownAt != 0 && now - shownAt > TTL_MS) {
            clear("ttl " + (TTL_MS / 1000) + "s");
            rgiOwns = false;
            lastKey = null;
        }
    }

    /* ---- CarPlay route guidance (RgiReceiver) -------------------------- */

    synchronized void rgiConnected(boolean up) {
        rgiLink = up;
        if (!up && rgiOwns) {
            clear("phone link lost");
            rgiOwns = false;
            lastKey = null;
            arrivedAt = 0;
        }
    }

    synchronized void rgiSnapshot(Hashtable s) {
        if (new File(OFF_FILE).exists()) return;
        int rs = num(s, "route_state", -1);
        long now = System.currentTimeMillis();

        if (rs == 0) {                                  /* NO_ROUTE_SET: route ended / cancelled */
            if (rgiOwns) clear("route ended");
            rgiOwns = false;
            lastKey = null;
            arrivedAt = 0;
            return;
        }
        if (rs == 2) {                                  /* ARRIVED */
            if (arrivedAt == 0) {
                show(ManeuverMap.ARRIVED, ManeuverMap.STRAIGHT, 0, 0, "");
                rgiOwns = true;
                arrivedAt = now;
                lastKey = "arrived";
                log("rgi: arrived");
            }
            return;
        }
        if (rs != 1 && rs != 6) return;                 /* loading / locating / rerouting: keep */
        arrivedAt = 0;

        int[] list = slots(str(s, "maneuver_list"));
        if (list.length == 0) return;
        int slot = list[0];
        if (num(s, "m" + slot + "_type", -1) == ManeuverMap.T_START_ROUTE && list.length > 1)
            slot = list[1];                             /* skip "proceed to the route" */
        String p = "m" + slot + "_";
        int type = num(s, p + "type", -1);
        if (type < 0) return;
        int angle = num(s, p + "exit_angle", ManeuverMap.NO_ANGLE);
        int side = num(s, p + "driving_side", 0);
        String street = str(s, p + "after_road");
        if (street.length() == 0) street = str(s, p + "name");
        if (street.length() > 60) street = street.substring(0, 60);

        String[] d = distance(s);
        int tenths = tenths(d[0]);
        int unit = unitCode(d[1]);

        String key = slot + "/" + str(s, p + "ver") + "/" + type + "/" + street;
        if (!key.equals(lastKey)) {
            int[] m = ManeuverMap.map(type, angle, side);
            show(m[0], m[1], tenths, unit, street);
            log("rgi: maneuver slot=" + slot + " type=" + type + " angle=" + angle
                + " -> main=" + m[0] + " dir=" + m[1] + " dist=" + d[0] + " " + d[1]);
            rgiOwns = true;
            lastKey = key;
            lastTenths = tenths;
            lastUnit = unit;
            lastDistAt = now;
            upSince = 0;
            return;
        }
        if ((tenths != lastTenths || unit != lastUnit) && now - lastDistAt >= DIST_MIN_MS
                && acceptDistance(tenths, unit, now)) {
            navi.updateDistanceToNextManeuver(tenths, unit, false, 0);
            lastTenths = tenths;
            lastUnit = unit;
            lastDistAt = now;
            upSince = 0;
        }
        shownAt = now;
    }

    private boolean acceptDistance(int tenths, int unit, long now) {
        if (lastTenths < 0) return true;
        double cur = meters(lastTenths, lastUnit);
        double nxt = meters(tenths, unit);
        if (nxt <= cur) return true;
        double rise = nxt - cur;
        if (rise < DIST_UP_MIN_M || rise < cur * 0.2) {
            upSince = 0;
            return false;
        }
        if (upSince == 0) {
            upSince = now;
            return false;
        }
        return now - upSince >= DIST_UP_HOLD_MS;
    }

    /* BAP tenths of a unit -> meters (unit codes as in unitCode) */
    private static double meters(int tenths, int unit) {
        double v = tenths / 10.0;
        switch (unit) {
            case 0: return v;               /* m */
            case 1: return v * 1000.0;      /* km */
            case 2: return v * 0.9144;      /* yd */
            case 3: return v * 0.3048;      /* ft */
            case 4: return v * 1609.344;    /* mi */
            default: return v;
        }
    }

    /* phone's own display string + units (0 km, 1 mi, 2 m, 3 yd, 4 ft) */
    private static String[] distance(Hashtable s) {
        String txt = cleanNumber(str(s, "dist_maneuver_str"));
        int u = num(s, "dist_maneuver_units", -1);
        String unit = u == 0 ? "km" : u == 1 ? "mi" : u == 2 ? "m" : u == 3 ? "yd" : u == 4 ? "ft" : null;
        if (txt.length() == 0 || unit == null) {
            int meters = num(s, "dist_maneuver_m", 0);
            if (meters < 0) meters = 0;
            if (meters >= 1000) {
                int t = (meters + 50) / 100;            /* tenths of km */
                return new String[] { (t / 10) + "." + (t % 10), "km" };
            }
            return new String[] { String.valueOf(meters), "m" };
        }
        return new String[] { txt, unit };
    }

    /* "0,5" -> "0.5"; drop anything that is not a digit or the first dot */
    private static String cleanNumber(String v) {
        StringBuffer b = new StringBuffer();
        boolean dot = false;
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c >= '0' && c <= '9') b.append(c);
            else if ((c == '.' || c == ',') && !dot) { b.append('.'); dot = true; }
        }
        String r = b.toString();
        if (r.equals(".")) return "";
        if (r.endsWith(".")) r = r.substring(0, r.length() - 1);
        if (r.startsWith(".")) r = "0" + r;
        return r;
    }

    private static int[] slots(String v) {
        String[] parts = splitChar(v, ',');
        int[] out = new int[parts.length];
        int n = 0;
        for (int i = 0; i < parts.length; i++) {
            try { out[n] = Integer.parseInt(parts[i].trim()); n++; } catch (Throwable ignored) { }
        }
        int[] r = new int[n];
        System.arraycopy(out, 0, r, 0, n);
        return r;
    }

    private static String[] splitChar(String s, char sep) {
        java.util.Vector v = new java.util.Vector();
        int i = 0;
        while (s.length() > 0) {
            int j = s.indexOf(sep, i);
            if (j < 0) { v.addElement(s.substring(i)); break; }
            v.addElement(s.substring(i, j));
            i = j + 1;
        }
        String[] out = new String[v.size()];
        v.copyInto(out);
        return out;
    }

    private static String str(Hashtable s, String k) {
        Object v = s.get(k);
        return v == null ? "" : v.toString();
    }

    private static int num(Hashtable s, String k, int dflt) {
        Object v = s.get(k);
        if (v == null) return dflt;
        try {
            return (int) Long.parseLong(v.toString().trim());
        } catch (Throwable t) {
            return dflt;
        }
    }

    private synchronized void handle(String line) {
        log("cmd: " + line);
        String[] w = split(line);
        if (w.length == 0) return;
        try {
            if ("STOP".equals(w[0])) {
                clear("STOP");
            } else if ("RGTYPE".equals(w[0]) && w.length >= 2) {
                rgType = Integer.parseInt(w[1]);
                log("rgType for syncs = " + rgType + " (applied on next start)");
            } else if ("TURN".equals(w[0]) && w.length >= 5) {
                int main = Integer.parseInt(w[1]);
                int dir = Integer.parseInt(w[2]);
                int tenths = tenths(w[3]);
                int unit = unitCode(w[4]);
                StringBuffer street = new StringBuffer();
                for (int i = 5; i < w.length; i++) {
                    if (street.length() > 0) street.append(' ');
                    street.append(w[i]);
                }
                show(main, dir, tenths, unit, street.toString());
            } else if ("DIST".equals(w[0]) && w.length >= 3) {
                /* countdown only: no sync, no maneuver change */
                int tenths = tenths(w[1]);
                int unit = unitCode(w[2]);
                navi.updateDistanceToNextManeuver(tenths, unit, false, 0);
                log("distance " + tenths + "/10 unit=" + unit);
                shownAt = System.currentTimeMillis();
            } else {
                log("unknown command");
            }
        } catch (Throwable t) {
            log("command failed: " + t);
        }
    }

    /*
     * BAP function synchronisation (FunctionSynchronizationNavi, MU1416):
     *   START_STOP_ROUTE_GUIDANCE (started by every updateRGStatus call)
     *       waits for fct 17, 39, 23, 18, 49
     *   CHANGE_OF_MANEUVER (started by updateManeuverDescriptor)
     *       waits for fct 23, 18, 49
     * A function that is never sent holds the arrow back until the 20 s
     * IncompleteSynchronizationTimeoutTimer fires - two such syncs in a row
     * were the ~40 s delay seen on the car. So: always send the complete set,
     * and never call updateRGStatus again while guidance is already active.
     *
     * 39 ActiveRGType: stock sends 4 for map-capable clusters (FPK/MMI).
     * 49 ExitView: stock NAR variant 1, id 0 = no exit view.
     */
    private void show(int main, int dir, int tenths, int unit, String street) {
        if (!active) {
            navi.updateRGStatus(1);
            navi.updateActiveRGType(rgType);
            log("start: updateRGStatus(1) + updateActiveRGType(" + rgType + ")");
            active = true;
        }
        CombiBAPNaviManeuverDescriptor d =
            new CombiBAPNaviManeuverDescriptor(main, dir, 0, new byte[0]);
        navi.updateManeuverDescriptor(new CombiBAPNaviManeuverDescriptor[] { d });
        navi.updateDistanceToNextManeuver(tenths, unit, false, 0);
        navi.updateExitView(EXITVIEW_VARIANT_NAR, 0);
        navi.updateTurnToInfo(street, "");
        log("maneuver main=" + main + " dir=" + dir + " dist=" + tenths + "/10 unit=" + unit
            + " street='" + street + "' (+exitView)");
        shownAt = System.currentTimeMillis();
    }

    private void clear(String why) {
        try {
            navi.updateRGStatus(0);
            navi.updateActiveRGType(rgType);
            navi.updateManeuverDescriptor(new CombiBAPNaviManeuverDescriptor[] {
                new CombiBAPNaviManeuverDescriptor(0, 0, 0, new byte[0]) });
            navi.updateDistanceToNextManeuver(-1, 255, false, 0);
            navi.updateExitView(EXITVIEW_VARIANT_NAR, 0);
            navi.updateTurnToInfo("", "");
            log("cleared (" + why + ")");
        } catch (Throwable t) {
            log("clear failed: " + t);
        }
        active = false;
        shownAt = 0;
    }

    /* "300" -> 3000, "0.5" -> 5: BAP carries distances in tenths of the unit */
    private static int tenths(String s) {
        int dot = s.indexOf('.');
        if (dot < 0) return Integer.parseInt(s) * 10;
        int whole = dot == 0 ? 0 : Integer.parseInt(s.substring(0, dot));
        String frac = s.substring(dot + 1);
        int first = frac.length() > 0 ? frac.charAt(0) - '0' : 0;
        return whole * 10 + first;
    }

    /* ft / mi / km / m, or a raw BAP unit code */
    private static int unitCode(String s) {
        if ("ft".equals(s)) return 3;
        if ("mi".equals(s)) return 4;
        if ("km".equals(s)) return 1;
        if ("m".equals(s)) return 0;
        if ("yd".equals(s)) return 2;
        return Integer.parseInt(s);
    }

    private static String[] split(String s) {
        java.util.Vector v = new java.util.Vector();
        int i = 0, n = s.length();
        while (i < n) {
            while (i < n && s.charAt(i) == ' ') i++;
            int j = i;
            while (j < n && s.charAt(j) != ' ') j++;
            if (j > i) v.addElement(s.substring(i, j));
            i = j;
        }
        String[] out = new String[v.size()];
        v.copyInto(out);
        return out;
    }

    private static String readFirstLine(File f) {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(f));
            return r.readLine();
        } catch (Throwable t) {
            return null;
        } finally {
            try { if (r != null) r.close(); } catch (Throwable ignored) { }
        }
    }

    static void log(String msg) {
        FileWriter w = null;
        try {
            w = new FileWriter(LOG_FILE, true);
            w.write(System.currentTimeMillis() / 1000 + " " + msg + "\n");
        } catch (Throwable ignored) {
        } finally {
            try { if (w != null) w.close(); } catch (Throwable ignored) { }
        }
    }
}
