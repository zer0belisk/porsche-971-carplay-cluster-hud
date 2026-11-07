/* carplay_hook_v37.c — attack the REAL cause: decoder bandwidth.
 *
 * sloginfo finally told the whole story, one second before a crash:
 *
 *   Late frame (88 ms, 2270 total late frames)      <- for MINUTES beforehand
 *   [AirPlayReceiverSessionScreen] ProcessFrames Error: -6753 kConnectionErr
 *   [AirPlayReceiverSessionScreen] StopSession
 *   UpdateState READY -> STOPPING
 *   [NvssVideoImpl] [stop] Stopped.
 *   UpdateState STOPPING -> STOPPED
 *   run fault ... ip 0x783af1f4
 *
 * So the chain is: our second 30 fps stream starves the hardware decoder, the
 * main screen runs ~88 ms late for thousands of frames, its connection finally
 * errors out, AirPlay tears the session down - and THAT teardown, with two NvSS
 * streams alive, is where libKD dies.
 *
 * Six builds went into the teardown, which is the symptom. The cause is that
 * one Tegra 2 decoder cannot carry two 30 fps streams. So: ask the phone for
 * fewer frames (maxFPS in the cluster dict, which we were setting to 30), and
 * keep a second lever to drop frames on our side if the phone ignores it.
 *
 * Both are runtime-tunable, because the right number has to be measured
 * against "total late frames" in sloginfo, not guessed.
 *
 * Reported on the car 2026-11-05, with v28 (which touches no video code, so
 * these are v27 defects that tuning inside CarPlay never hit):
 *   1. leaving CarPlay for any other menu crashes the session; BOTH screens
 *      drop and CarPlay reconnects;
 *   2. the cluster map sometimes freezes on one frame while the centre screen
 *      keeps working normally;
 *   3. sometimes it does not come up at all.
 *
 * (1) and (2) are consistent with one cause: we run a SECOND NvssVideoImpl
 * against the same NvSS device as the stock one. When the HMI drops the main
 * screen it tears its instance down, and if that closes the shared NvSS
 * session our handle dies with it — a dead handle explains both a crash in
 * decode and a silently frozen plane.
 *
 * This build does NOT guess at a fix. It does two things:
 *   - INSTRUMENTS the stock teardown path (ScreenStreamStop, NvSSVideoClose)
 *     so the log says whether the crash really follows a stock close, and
 *     whether the handle being closed is ours or theirs;
 *   - adds a STALL WATCHDOG, which is correct whatever the cause: if no frame
 *     decodes for STALL_SEC, the cluster goes back to the Porsche map instead
 *     of showing the driver a frozen one, and re-claims if frames return.
 *
 * (3) may simply be v28's self-disarm doing its job; the log says which.
 *
 *
 * Why v28: /tmp on this unit is /dev/shmem, a ramdisk. Parking the car power
 * cycles the PCM, /tmp/hook_level disappears, and the next drive is back to
 * stock with the cluster on the Porsche map. v28 resolves settings from
 * /tmp -> PERSIST_DIR -> compiled defaults, and defaults to level 7, so the
 * feature stays on until it is deliberately turned off.
 *
 * That removes the old "any reboot returns the car to stock" safety net, so
 * two guards replace it:
 *   - self-disarm: DISARM_AFTER consecutive connects that inject the cluster
 *     but never reach ScreenStreamCreate turn the hook into a passthrough for
 *     the rest of the boot. A teardown loop can no longer leave the driver
 *     without CarPlay and without a laptop.
 *   - stale-claim recovery: a marker file in /tmp records that the cluster
 *     points at our context, so a session that follows a hard kill puts the
 *     stock map back.
 * `echo 0 > /tmp/hook_level` still disarms instantly.
 *
 * Why: on level 3 the phone offers stream 111, stock 210.81 cannot serve it,
 * returns no dataPort, and iOS aborts the session before it ever SETUPs stream
 * 110 -> main CarPlay stays black. Measured on the car 2026-11-05.
 * v12 answers that SETUP with a real dataPort from our own listener, so the
 * session should survive and main CarPlay should come up.
 *
 * LEVEL GATE (deliberate, keeps a bisect point):
 *   0 passthrough | 1 main /info | 2 +cluster | 3 +extendedFeatures (v10/v11 behaviour)
 *   4 = level 3 PLUS the 111 receiver.  Only level 4 opens a socket.
 *
 * Offsets verified on OUR MU1416 libairplay (analysis/FINDINGS_MU1416.md s.3):
 *   OFF_SERVER 12, OFF_FAMILY 85, OFF_AESKEY 456, SVR_OFF_QOSDISABLED 452.
 * v12 RESULT on the car (2026-11-05): session SURVIVED — SETUP 110 arrived,
 * ScreenStreamCreate/Start #1 fired, main CarPlay worked. But the phone never
 * connected to our data port: "alt: no connection".
 * ROOT CAUSE: wired CarPlay runs on interface carplay0, whose pf policy ends in
 *   block drop in quick on carplay0 all
 * and allows inbound TCP only on 5000-5001, 5010, 6000-6001, 6030, 6100, 6200,
 * 7000-7001, 7100.  Stock stream 110 uses 6030 (hence ServerSocketOpen -6030).
 * Our -6031 is NOT in that list -> the SYN was silently dropped.
 * v13 therefore asks for a pf-ALLOWED port and refuses to publish a port that
 * is not on the allowlist, instead of handing iOS a dead dataPort.
 *
 * v13 RESULT on the car: port 6100 taken, "111 ANSWERED with dataPort=6100",
 * "111 CONNECTION ACCEPTED fd=37" — the phone DID connect — and main CarPlay
 * still came up (SETUP 110 + ScreenStreamCreate/Start #1).  But the very first
 * read failed: "stream ended frames=0 bytes=0 errno=11" = EAGAIN.  The socket
 * handed back by SocketAccept is NON-BLOCKING, and v13 treated any r<=0 that
 * was not EINTR as end-of-stream.
 * v14 fixes exactly that: EAGAIN/EWOULDBLOCK now waits for readability with
 * select() instead of being read as EOF, so the thread stays cancellable.
 *
 * v14 RESULT on the car: FULL SUCCESS. 2100 frames / 12.8 MB, ~31 fps, ~900 kbit/s,
 * socket fe80::...6100 ESTABLISHED, main CarPlay alive the whole time.
 * Wire format confirmed: frame #1 op=1 body=39 (avcC config, plaintext),
 * then op=0 bodies (AES-CTR encrypted AVCC access units).
 *
 * v15 adds the next step: decrypt op=0 bodies with the session AES-CTR context
 * (ONE context for the whole session — CTR is a stream cipher, so every
 * encrypted body must pass through it in order or the keystream desyncs), turn
 * avcC + AVCC length-prefixed NALUs into Annex-B, and dump to DUMP_PATH so the
 * stream can be verified off-car with ffprobe.  The dump is byte-capped; once the
 * cap is hit we keep decrypting (to preserve keystream sync) but stop writing.
 *
 * v11 lineage: v10 + build-overridable cluster geometry and the
 * reference-verified view-area safe rects. Hook logic is UNCHANGED from v10.
 * v10 lineage: faithful port of luka-dev altScreen advert for Porsche MHI2/POG24.
 * Key fixes vs our v3-v7: cluster AND main carry "uid"(=display uuid) + non-empty
 * "initialVideoStreams"; full field set; 3 viewAreas with safe frames. */
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>

#define HOOK_LOG  "/tmp/carplay_hook.log"
#define DUMP_PATH "/tmp/cluster.h264"
#ifndef DUMP_CAP
#define DUMP_CAP  (8u*1024*1024)
#endif
#define LEVEL_FILE "/tmp/hook_level"
/* ---- persistent settings (v28) -------------------------------------------
 * /tmp is /dev/shmem, a ramdisk: everything there dies with the PCM, which is
 * why the car came back to stock after being parked. Settings are now looked
 * up in three tiers:
 *     1. /tmp/<name>                       live override, wins, dies on reboot
 *     2. PERSIST_DIR/<name>                survives reboot, set by the installer
 *     3. the compiled defaults below       survive everything
 * The persistent tier is read ONCE in the constructor. /tmp stays live, so
 * `echo 0 > /tmp/hook_level` still disarms the hook instantly. */
#ifndef PERSIST_DIR
#define PERSIST_DIR "/mnt/app/eso/lib"
#endif
/* Default level when no file exists in either tier. 7 = full feature.
 * Build with -DDEFAULT_LEVEL=0 for the old "reboot returns to stock" behaviour. */
#ifndef DEFAULT_LEVEL
#define DEFAULT_LEVEL 7
#endif
/* Self-disarm: if this many connects in a row inject the cluster and never
 * reach ScreenStreamCreate (i.e. main CarPlay does not come up), stop
 * injecting for the rest of this boot. Without it, default-on would mean a
 * teardown loop leaves the driver with no CarPlay and no way out but SSH. */
#ifndef DISARM_AFTER
#define DISARM_AFTER 3
#endif
#define FAIL_FILE   "/tmp/alt_failcnt"
#define CLAIM_FILE  "/tmp/alt_ctx_claimed"
/* v37: frames per second we ASK the phone for on the cluster stream. 30 is
 * what starved the decoder. Overridable at build time and at runtime. */
#ifndef CLUSTER_FPS
#define CLUSTER_FPS 15
#endif
/* v37: feed only every (alt_skip+1)-th frame to our decoder. Second lever, in
 * case the phone ignores maxFPS. 0 = feed everything. */
#define SKIP_FILE "/tmp/alt_skip"
#define REBUILD_FILE "/tmp/alt_rebuild"

/* Open <name> from the live tier, then the persistent tier. */
static FILE *cfg_open(const char *name){
    char path[256]; FILE *f;
    snprintf(path,sizeof path,"/tmp/%s",name);
    if((f=fopen(path,"r"))) return f;
    snprintf(path,sizeof path,"%s/%s",PERSIST_DIR,name);
    return fopen(path,"r");
}
#define CFENC_UTF8 0x08000100u
#define CLUSTER_UUID "C1057E12-A0D1-4E20-B0C0-1057E12A0D10"
#define CLUSTER_URL  "maps:/car/instrumentcluster"
/* ---- cluster geometry -------------------------------------------------------
 * STILL AUDI-DERIVED. The real 971 values are unknown until measured on the car
 * with the read-only command:   /eso/bin/apps/dmdt gs
 * (prints "<name> / LVDS2 / <W>x<H> / ctx <n>" per display; our cluster = display id 4).
 * Every value below is overridable at build time, e.g.
 *   -DCLUSTER_W=1280 -DCLUSTER_H=480
 * so no source edit is needed once dmdt reports the real panel.
 * Safe areas are the reference's VERIFIED Audi values (altscreen_hook.c:356-371),
 * not the ad-hoc ones v10 carried.
 * NOTE: a safe area narrower than ~498 px makes iOS log
 * "Undefined layout (0), will not show cluster content" and hide ETA / turn card
 * for THIRD-PARTY apps — which includes Waze, our actual target. Keep the
 * fullscreen view area wide. */
#ifndef CLUSTER_W
#define CLUSTER_W 1440
#endif
#ifndef CLUSTER_H
#define CLUSTER_H 542
#endif
#ifndef CLUSTER_PHYS_W
#define CLUSTER_PHYS_W 152
#endif
#ifndef CLUSTER_PHYS_H
#define CLUSTER_PHYS_H 91
#endif
/* fullscreen view area safe rect (ref verified: 330, 88, 780x294) */
#ifndef FULL_SAFE_X
#define FULL_SAFE_X 330
#endif
#ifndef FULL_SAFE_Y
#define FULL_SAFE_Y 88
#endif
#ifndef FULL_SAFE_W
#define FULL_SAFE_W 780
#endif
#ifndef FULL_SAFE_H
#define FULL_SAFE_H 294
#endif
/* sport ("smallscreen") safe rect (ref verified: 108, 88, 348x294) */
#ifndef SS_SAFE_X
#define SS_SAFE_X 108
#endif
#ifndef SS_SAFE_Y
#define SS_SAFE_Y 88
#endif
#ifndef SS_SAFE_W
#define SS_SAFE_W 348
#endif
#ifndef SS_SAFE_H
#define SS_SAFE_H 294
#endif
/* classic safe rect (ref verified: 540, 88, 360x294) — v10 wrongly reused sport */
#ifndef CL_SAFE_X
#define CL_SAFE_X 540
#endif
#ifndef CL_SAFE_Y
#define CL_SAFE_Y 88
#endif
#ifndef CL_SAFE_W
#define CL_SAFE_W 360
#endif
#ifndef CL_SAFE_H
#define CL_SAFE_H 294
#endif

static void lg(const char *fmt, ...){ FILE*f=fopen(HOOK_LOG,"a"); if(!f)return; char b[512]; va_list ap; va_start(ap,fmt); vsnprintf(b,sizeof b,fmt,ap); va_end(ap); fprintf(f,"%ld %s\n",(long)time((time_t*)0),b); fclose(f); }

typedef void* (*cf_str_t)(void*,const char*,uint32_t);
typedef void* (*cf_arrm_t)(void*,long,const void*);
typedef int   (*cf_arrappc_t)(void*,const char*,long);
typedef void  (*cf_arrapp_t)(void*,const void*);
typedef void  (*cf_rel_t)(const void*);
typedef void  (*cf_dictset_t)(void*,const void*,const void*);
typedef void* (*cf_dictm_t)(void*,long,const void*,const void*);
typedef int   (*cf_dictseti_t)(void*,const void*,int64_t);
typedef void* (*cf_dictgetval_t)(void*,const void*);
typedef long  (*cf_arrcnt_t)(void*);
typedef void* (*cf_arrget_t)(void*,long);
typedef int64_t (*cf_dictgeti_t)(void*,const void*,int*);
typedef int   (*fn_sess_setup_t)(void*,void*,void**,int);
typedef void* (*fn_copydisp_t)(void*,int*);
typedef void* (*fn_copyinfo_t)(void*,void*,void*,void*);

static cf_str_t cf_str; static cf_arrm_t cf_arrm; static cf_arrappc_t cf_arrappc;
static cf_arrapp_t cf_arrapp; static cf_rel_t cf_rel; static cf_dictset_t cf_dictset;
static cf_dictm_t cf_dictm; static cf_dictseti_t cf_dictseti; static cf_dictgetval_t cf_getval;
static cf_arrcnt_t cf_arrcnt; static cf_arrget_t cf_arrget; static cf_dictgeti_t cf_geti64;
static fn_copydisp_t fn_copydisp;
static const void *arr_cb,*dict_keycb,*dict_valcb; static int cf_ok=-1;

static int cf_init(void){
    if(cf_ok==1) return 1;
    cf_str=(cf_str_t)dlsym(RTLD_DEFAULT,"CFStringCreateWithCString");
    cf_arrm=(cf_arrm_t)dlsym(RTLD_DEFAULT,"CFArrayCreateMutable");
    cf_arrappc=(cf_arrappc_t)dlsym(RTLD_DEFAULT,"CFArrayAppendCString");
    cf_arrapp=(cf_arrapp_t)dlsym(RTLD_DEFAULT,"CFArrayAppendValue");
    cf_rel=(cf_rel_t)dlsym(RTLD_DEFAULT,"CFRelease");
    cf_dictset=(cf_dictset_t)dlsym(RTLD_DEFAULT,"CFDictionarySetValue");
    cf_dictm=(cf_dictm_t)dlsym(RTLD_DEFAULT,"CFDictionaryCreateMutable");
    cf_dictseti=(cf_dictseti_t)dlsym(RTLD_DEFAULT,"CFDictionarySetInt64");
    cf_getval=(cf_dictgetval_t)dlsym(RTLD_DEFAULT,"CFDictionaryGetValue");
    cf_arrcnt=(cf_arrcnt_t)dlsym(RTLD_DEFAULT,"CFArrayGetCount");
    cf_arrget=(cf_arrget_t)dlsym(RTLD_DEFAULT,"CFArrayGetValueAtIndex");
    cf_geti64=(cf_dictgeti_t)dlsym(RTLD_DEFAULT,"CFDictionaryGetInt64");
    fn_copydisp=(fn_copydisp_t)dlsym(RTLD_DEFAULT,"AirPlayReceiverSessionScreen_CopyDisplaysInfo");
    arr_cb=dlsym(RTLD_DEFAULT,"kCFLArrayCallBacksCFLTypes"); if(!arr_cb)arr_cb=dlsym(RTLD_DEFAULT,"kCFTypeArrayCallBacks");
    dict_keycb=dlsym(RTLD_DEFAULT,"kCFLDictionaryKeyCallBacksCFLTypes");
    dict_valcb=dlsym(RTLD_DEFAULT,"kCFLDictionaryValueCallBacksCFLTypes");
    if(cf_str&&cf_arrm&&cf_arrapp&&cf_rel&&cf_dictset&&cf_dictm&&cf_dictseti&&cf_getval&&arr_cb&&dict_keycb&&dict_valcb){cf_ok=1;return 1;}
    lg("cf_init FAILED"); cf_ok=0; return 0;
}
static int set_str(void*d,const char*k,const char*v){ void*kk=cf_str(0,k,CFENC_UTF8),*vv=cf_str(0,v,CFENC_UTF8); if(kk&&vv)cf_dictset(d,kk,vv); if(vv)cf_rel(vv); if(kk)cf_rel(kk); return (kk&&vv)?0:-1; }
static int set_i64(void*d,const char*k,int64_t v){ void*kk=cf_str(0,k,CFENC_UTF8); int rc=kk?cf_dictseti(d,kk,v):-1; if(kk)cf_rel(kk); return rc; }
static int alt_physw = CLUSTER_PHYS_W, alt_physh = CLUSTER_PHYS_H;
static int alt_fps   = CLUSTER_FPS;     /* maxFPS announced for the cluster */
static int alt_skip  = 0;               /* feed every (alt_skip+1)-th frame */
/* v48: 1 = presentation stamps from the monotonic clock (default),
 * 0 = the old fixed 1/fps step. Runtime file /tmp/alt_ptsmode. */
static int alt_ptsmode = 1;

/* Optional 7th field of /tmp/alt_disp is the fps, so the existing 6-field
 * files keep working. /tmp/alt_skip is a single number. */
static void alt_fps_load(void){
    char buf[64]; int n, v;
    FILE*f=cfg_open("alt_fps");
    if(f){ n=(int)fread(buf,1,sizeof(buf)-1,f); fclose(f);
           if(n>0){ buf[n]=0; if(sscanf(buf,"%d",&v)==1 && v>0 && v<=60){
               alt_fps=v; lg("alt-fps: announcing maxFPS=%d (from file)",alt_fps); return; } } }
    lg("alt-fps: announcing maxFPS=%d (compiled)",alt_fps);
}
static void alt_ptsmode_load(void){
    char buf[32]; int n,v;
    FILE*f=cfg_open("alt_ptsmode");
    if(!f) return;
    n=(int)fread(buf,1,sizeof(buf)-1,f); fclose(f);
    if(n>0){ buf[n]=0; if(sscanf(buf,"%d",&v)==1 && (v==0||v==1)){
        if(v!=alt_ptsmode){ alt_ptsmode=v;
            lg("alt-pts: mode %d (%s)",v,v?"monotonic clock":"fixed 1/fps step"); } } }
}
static void alt_skip_load(void){
    char buf[64]; int n, v;
    FILE*f=fopen(SKIP_FILE,"r");
    if(!f) return;
    n=(int)fread(buf,1,sizeof(buf)-1,f); fclose(f);
    if(n>0){ buf[n]=0; if(sscanf(buf,"%d",&v)==1 && v>=0 && v<=9){
        if(v!=alt_skip){ alt_skip=v;
            lg("alt-skip: feeding every %d-th frame",alt_skip+1); } } }
}
static int alt_safe[4] = { FULL_SAFE_X, FULL_SAFE_Y, FULL_SAFE_W, FULL_SAFE_H };

/* Read once at load (constructor), never during /info construction. */
static void alt_disp_load(void){
    char buf[128]; int n, v[6];
    FILE*f=cfg_open("alt_disp");
    if(!f){ lg("alt-disp: no alt_disp file, using compiled %dx%d mm safe %d,%d %dx%d",
               alt_physw,alt_physh,alt_safe[0],alt_safe[1],alt_safe[2],alt_safe[3]); return; }
    n=(int)fread(buf,1,sizeof(buf)-1,f); fclose(f);
    if(n<=0){ return; }
    buf[n]=0;
    if(sscanf(buf,"%d %d %d %d %d %d",&v[0],&v[1],&v[2],&v[3],&v[4],&v[5])==6){
        alt_physw=v[0]; alt_physh=v[1];
        alt_safe[0]=v[2]; alt_safe[1]=v[3]; alt_safe[2]=v[4]; alt_safe[3]=v[5];
        lg("alt-disp: phys=%dx%d mm safe=%d,%d %dx%d (from file)",
           alt_physw,alt_physh,alt_safe[0],alt_safe[1],alt_safe[2],alt_safe[3]);
    } else lg("alt-disp: need 6 numbers (physW physH safeX safeY safeW safeH)");
}

static void*build_rect(int64_t x,int64_t y,int64_t w,int64_t h){ void*d=cf_dictm(0,0,dict_keycb,dict_valcb); if(!d)return 0; if(set_i64(d,"originXPixels",x)||set_i64(d,"originYPixels",y)||set_i64(d,"widthPixels",w)||set_i64(d,"heightPixels",h)){cf_rel(d);return 0;} return d; }
static void*build_viewarea(int64_t x,int64_t y,int64_t w,int64_t h,int64_t sx,int64_t sy,int64_t sw,int64_t sh){ void*va=build_rect(x,y,w,h); if(!va)return 0; void*safe=build_rect(sx,sy,sw,sh); void*k=safe?cf_str(0,"safeArea",CFENC_UTF8):0; if(!safe||!k){if(k)cf_rel(k);if(safe)cf_rel(safe);cf_rel(va);return 0;} cf_dictset(va,k,safe); cf_rel(k); cf_rel(safe); return va; }
static void*build_stream_array(const char*uuid){ void*arr=cf_arrm(0,1,arr_cb); if(!arr)return 0; void*d=cf_dictm(0,0,dict_keycb,dict_valcb); if(!d){cf_rel(arr);return 0;} if(set_i64(d,"originXPixels",0)||set_i64(d,"originYPixels",0)||set_str(d,"uuid",uuid)||set_i64(d,"zIndex",0)){cf_rel(d);cf_rel(arr);return 0;} cf_arrapp(arr,d); cf_rel(d); return arr; }

/* v60: bisect the cluster display dictionary without rebuilding.
 *   echo "properties viewAreas" > /tmp/alt_omit
 * Each named key is then left out of the dict we inject into /info.
 * Known so far: level 1 (main display only) survives an Apple Maps route,
 * level 2 (the cluster entry added) does not - so the breakage is one of
 * these keys, not the altScreen protocol we spent the evening on. */
static int alt_omit(const char *key){
    static char buf[256]; static int loaded; static time_t last;
    time_t now=time(0);
    if(!loaded || now!=last){
        FILE *f=cfg_open("alt_omit");
        buf[0]=0; loaded=1; last=now;
        if(f){ int n=(int)fread(buf,1,sizeof(buf)-1,f); fclose(f); buf[n>0?n:0]=0; }
    }
    return buf[0] && strstr(buf,key)!=0;
}

static const char *alt_scene_url(void);
static void*build_cluster_dict(void){
    void*d=cf_dictm(0,0,dict_keycb,dict_valcb); if(!d)return 0;
    /* v61: the display type, switchable at runtime. Bisection showed that the
     * mere presence of a type-111 display in /info is what breaks an Apple Maps
     * route on this firmware - with every optional key stripped out. Try other
     * values: iOS may still stream video to a secondary display that it does
     * not treat as an instrument cluster.  echo 110 > /tmp/alt_type */
    long cluster_type=111;
    { FILE*f=cfg_open("alt_type");
      if(f){ char b[16]; int n=(int)fread(b,1,sizeof b-1,f); fclose(f);
             b[n>0?n:0]=0; long v=strtol(b,0,10); if(v>0) cluster_type=v; } }
    lg("cluster dict: type=%ld",cluster_type);
    if(set_str(d,"name","Instrument Cluster")||set_i64(d,"type",cluster_type)||set_i64(d,"maxFPS",alt_fps)||
       set_i64(d,"widthPixels",CLUSTER_W)||set_i64(d,"heightPixels",CLUSTER_H)||
       set_i64(d,"widthPhysical",alt_physw)||set_i64(d,"heightPhysical",alt_physh)||
       set_str(d,"uid",CLUSTER_UUID)||set_str(d,"uuid",CLUSTER_UUID)) goto fail;
    if(!alt_omit("properties"))
    { void*k=cf_str(0,"properties",CFENC_UTF8); void*a=cf_arrm(0,1,arr_cb); int ok=0;
      if(a){ if(cf_arrappc) ok=(cf_arrappc(a,"Instrument Cluster",-1)==0);
             else { void*s=cf_str(0,"Instrument Cluster",CFENC_UTF8); if(s){cf_arrapp(a,s);ok=1;cf_rel(s);} }
             if(k&&ok)cf_dictset(d,k,a); cf_rel(a);} if(k)cf_rel(k); if(!ok)goto fail; }
    if(!alt_omit("viewAreas"))
    { void*k=cf_str(0,"viewAreas",CFENC_UTF8); void*a=cf_arrm(0,3,arr_cb); int ok=0;
      void*full=build_viewarea(0,0,CLUSTER_W,CLUSTER_H,alt_safe[0],alt_safe[1],alt_safe[2],alt_safe[3]);
      void*split=build_viewarea(0,0,CLUSTER_W,CLUSTER_H,SS_SAFE_X,SS_SAFE_Y,SS_SAFE_W,SS_SAFE_H);
      void*classic=build_viewarea(0,0,CLUSTER_W,CLUSTER_H,CL_SAFE_X,CL_SAFE_Y,CL_SAFE_W,CL_SAFE_H);
      if(a&&full&&split&&classic&&k){cf_arrapp(a,full);cf_arrapp(a,split);cf_arrapp(a,classic);cf_dictset(d,k,a);ok=1;}
      if(full)cf_rel(full); if(split)cf_rel(split); if(classic)cf_rel(classic); if(a)cf_rel(a); if(k)cf_rel(k);
      if(!ok)goto fail; }
    if(!alt_omit("viewAreas") && set_i64(d,"initialViewArea",0)) goto fail;
    { void*k=cf_str(0,"adjacentViewAreas",CFENC_UTF8); void*a=cf_arrm(0,0,arr_cb); if(k&&a)cf_dictset(d,k,a); if(a)cf_rel(a); if(k)cf_rel(k); }
    /* v72: initialURL is the scene the cluster window is CREATED with. iOS reads
     * /info once per session; the reference sets initialURL to the URL of the
     * current scene ("a pre-stream suggestion is satisfied by initialURL in
     * /info and by first-IDR showUI"). We had the bare root here from day one -
     * maps:/car/instrumentcluster = anyContent - so Apple Maps built the cluster
     * scene for any content and put its full-screen turn card there during
     * guidance; every later showUI "map only" was accepted (status 0) and had
     * no visible effect. Same URL as showUI now. */
    { const char *iu=alt_scene_url();
      if(!iu) iu=CLUSTER_URL;
      lg("cluster dict: initialURL=%s",iu);
      if(!alt_omit("initialURL") && set_str(d,"initialURL",iu)) goto fail; }
    if(!alt_omit("extras")){ set_i64(d,"cornerMasks",0); set_i64(d,"nightMode",0); set_i64(d,"limitedUI",0); }
    { void*k=cf_str(0,"limitedUIElements",CFENC_UTF8); void*a=cf_arrm(0,0,arr_cb); if(k&&a)cf_dictset(d,k,a); if(a)cf_rel(a); if(k)cf_rel(k); }
    if(!alt_omit("initialVideoStreams"))
    { void*k=cf_str(0,"initialVideoStreams",CFENC_UTF8); void*a=build_stream_array(CLUSTER_UUID); int ok=0;
      if(k&&a){cf_dictset(d,k,a);ok=1;} if(a)cf_rel(a); if(k)cf_rel(k); if(!ok)goto fail; }
    lg("cluster dict built (%dx%d)%s",CLUSTER_W,CLUSTER_H,
       alt_omit("x")||1?"":"");
    { const char *om[]={"properties","viewAreas","initialURL","extras","initialVideoStreams",0};
      int i; for(i=0;om[i];i++) if(alt_omit(om[i])) lg("cluster dict: '%s' OMITTED",om[i]); }
    return d;
fail: lg("cluster build FAILED"); cf_rel(d); return 0;
}

/* modernize stock main: add uid=real main uuid + initialVideoStreams keyed to real uuid */
static int main_modernize(void*m){
    if(!m) return -1;
    void*realUuid=0; { void*k=cf_str(0,"uuid",CFENC_UTF8); if(k&&cf_getval)realUuid=cf_getval(m,k); if(k)cf_rel(k); }
    if(!realUuid){ lg("main uuid missing"); return -1; }
    { void*k=cf_str(0,"uid",CFENC_UTF8); if(!k)return -1; cf_dictset(m,k,realUuid); cf_rel(k); }
    { void*k=cf_str(0,"initialVideoStreams",CFENC_UTF8);
      void*arr=cf_arrm(0,1,arr_cb); void*d=arr?cf_dictm(0,0,dict_keycb,dict_valcb):0; void*ku=d?cf_str(0,"uuid",CFENC_UTF8):0;
      int ok=0;
      if(k&&arr&&d&&ku){ set_i64(d,"originXPixels",0); set_i64(d,"originYPixels",0); cf_dictset(d,ku,realUuid); set_i64(d,"zIndex",0); cf_arrapp(arr,d); cf_dictset(m,k,arr); ok=1; }
      if(ku)cf_rel(ku); if(d)cf_rel(d); if(arr)cf_rel(arr); if(k)cf_rel(k);
      if(!ok){ lg("main ivs failed"); return -1; } }
    lg("main modernized (uid+ivs=real uuid)");
    return 0;
}

static void*build_displays(int with_cluster){
    int err=0; void*m=fn_copydisp?fn_copydisp(0,&err):0; if(!m){lg("no stock main err=%d",err);return 0;}
    if(main_modernize(m)){ cf_rel(m); return 0; }
    void*c=with_cluster?build_cluster_dict():0;
    if(with_cluster&&!c){ cf_rel(m); return 0; }
    void*arr=cf_arrm(0,2,arr_cb); if(!arr){cf_rel(m);if(c)cf_rel(c);return 0;}
    cf_arrapp(arr,m); cf_rel(m); if(c){cf_arrapp(arr,c);cf_rel(c);}
    return arr;
}
static void*build_extfeatures(void){ void*a=cf_arrm(0,2,arr_cb); if(!a)return 0; if(cf_arrappc){cf_arrappc(a,"altScreen",-1);cf_arrappc(a,"viewAreas",-1);} else {void*s=cf_str(0,"altScreen",CFENC_UTF8);if(s){cf_arrapp(a,s);cf_rel(s);}s=cf_str(0,"viewAreas",CFENC_UTF8);if(s){cf_arrapp(a,s);cf_rel(s);}} return a; }
static void*build_suggest_urls(void){ static const char*const u[]={"maps:/car/instrumentcluster","maps:/car/instrumentcluster/map","maps:/car/instrumentcluster/instructioncard","maps:/",0}; void*a=cf_arrm(0,4,arr_cb); if(!a)return 0; for(int i=0;u[i];i++){if(cf_arrappc)cf_arrappc(a,u[i],-1);else{void*s=cf_str(0,u[i],CFENC_UTF8);if(s){cf_arrapp(a,s);cf_rel(s);}}} return a; }

/* Level from the persistent tier, resolved once in the constructor.
 * -1 = no persistent file, fall through to DEFAULT_LEVEL. */
static int persist_level = -1;

static int read_level_file(const char *path){
    FILE *f=fopen(path,"r"); if(!f) return -1;
    int c=fgetc(f); fclose(f);
    if(c<'0'||c>'9') return -1;
    int n=c-'0'; if(n>7) n=7;
    return n;
}

static void persist_level_load(void){
    char path[256];
    snprintf(path,sizeof path,"%s/%s",PERSIST_DIR,"hook_level");
    persist_level=read_level_file(path);
    if(persist_level>=0) lg("level: persistent file says %d",persist_level);
    else lg("level: no persistent file, default %d",DEFAULT_LEVEL);
}

/* Count of consecutive connects that injected but never saw main CarPlay come
 * up. Lives in /tmp so it survives a dio_manager restart but not a reboot. */
static int fail_count(void){
    int n=read_level_file(FAIL_FILE);
    return n<0?0:n;
}
static void fail_write(int n){
    FILE*f=fopen(FAIL_FILE,"w");
    if(f){ fprintf(f,"%d\n",n); fclose(f); }
}

static int inject_level(void){
    /* tier 1: live override, present-with-0 must mean "off", not "absent" */
    int n=read_level_file(LEVEL_FILE);
    if(n<0) n=(persist_level>=0)?persist_level:DEFAULT_LEVEL;   /* tiers 2, 3 */
    if(n>0 && fail_count()>=DISARM_AFTER){
        static int said;            /* inject_level() runs dozens of times a
                                     * session; the log is the only diagnostic
                                     * we have, so say this once per process. */
        if(!said){ said=1;
            lg("*** SELF-DISARMED: %d connects in a row injected but main CarPlay "
               "never came up. Passthrough for the rest of this boot. "
               "Clear with: rm %s ***",fail_count(),FAIL_FILE); }
        return 0;
    }
    return n;
}
static void inject(void*info){
    int lvl=inject_level(); lg("inject level=%d",lvl);
    if(lvl<1){lg("passthrough (level 0)");return;}
    /* Armed for this connect. ScreenStreamCreate clears this again once the
     * main screen's stream exists; if it never does, we disarm after
     * DISARM_AFTER attempts. */
    /* Count once per dio_manager process, not per /info: iOS may ask for
     * /info more than once in a session, and dio restarts for each session,
     * so the process lifetime is the right unit for "one connect attempt". */
    { static int counted;
      if(!counted){ counted=1;
          int c=fail_count()+1; fail_write(c);
          lg("inject: attempt %d of %d before self-disarm",c,DISARM_AFTER); } }
    void*disp=build_displays(lvl>=2); if(!disp){lg("no displays");return;}
    void*dk=cf_str(0,"displays",CFENC_UTF8); void*pk=cf_str(0,"displayPanels",CFENC_UTF8);
    if(dk)cf_dictset(info,dk,disp); if(pk)cf_dictset(info,pk,disp);
    lg("set displays+displayPanels (cluster=%d)",lvl>=2);
    int nosuggest=0;
    { FILE*f=cfg_open("alt_nosuggest");
      if(f){ int c=fgetc(f); fclose(f); nosuggest=(c=='1'); } }
    if(lvl>=3){ void*feat=build_extfeatures(),*urls=nosuggest?0:build_suggest_urls(),*fk=cf_str(0,"extendedFeatures",CFENC_UTF8),*uk=cf_str(0,"altScreenSuggestUIURLs",CFENC_UTF8);
        if(nosuggest) lg("*** /info: altScreenSuggestUIURLs OMITTED (alt_nosuggest=1) — "
                         "testing whether iOS then stops sending suggestUI ***");
        if(feat&&fk)cf_dictset(info,fk,feat); if(urls&&uk)cf_dictset(info,uk,urls); lg("set extendedFeatures+altScreenSuggestUIURLs");
        if(fk)cf_rel(fk);if(uk)cf_rel(uk);if(feat)cf_rel(feat);if(urls)cf_rel(urls); }
    if(dk)cf_rel(dk); if(pk)cf_rel(pk); if(disp)cf_rel(disp);
}


/* ===================== SELF-CONTAINED TYPE-111 RECEIVER =====================
 * Port of luka-dev alt_setup, reduced to what keeps the session alive:
 * derive key -> open our own listener -> answer {type:111,dataPort} -> accept
 * and drain. No decrypt, no render yet: the goal of this step is that iOS gets
 * a usable dataPort, proceeds to SETUP 110, and main CarPlay comes up. */
#define OFF_SERVER          12
#define OFF_FAMILY          85
#define OFF_AESKEY          456
#define SVR_OFF_QOSDISABLED 452
#define ALT_STREAM_TYPE     111
#define ALT_HDR_SIZE        128
#define ALT_MAX_BODY        (4u*1024*1024)

typedef void (*fn_derive_aes_t)(const uint8_t*,int,uint64_t,uint8_t*,uint8_t*);
typedef int  (*fn_srv_sockopen_t)(int,int,int,int,int*,int,int*);
typedef void (*fn_sock_setqos_t)(int,int);
typedef int  (*fn_sock_accept_t)(int,int,int*,void*);
typedef int  (*fn_aes_init_t)(void*,const uint8_t*,const uint8_t*);
typedef int  (*fn_aes_upd_t)(void*,const uint8_t*,uint32_t,uint8_t*);
typedef int  (*fn_aes_fin_t)(void*);

static fn_derive_aes_t   fn_derive;
static fn_srv_sockopen_t fn_sockopen;
static fn_sock_setqos_t  fn_setqos;
static fn_sock_accept_t  fn_accept;
static fn_aes_init_t     fn_aes_init;
static fn_aes_upd_t      fn_aes_upd;
static fn_aes_fin_t      fn_aes_fin;
static int alt_syms_ok = -1;

static int alt_syms(void){
    if(alt_syms_ok>=0) return alt_syms_ok;
    fn_derive  =(fn_derive_aes_t)  dlsym(RTLD_DEFAULT,"AirPlay_DeriveAESKeySHA512ForScreen");
    fn_sockopen=(fn_srv_sockopen_t)dlsym(RTLD_DEFAULT,"ServerSocketOpen");
    fn_setqos  =(fn_sock_setqos_t) dlsym(RTLD_DEFAULT,"SocketSetQoS");
    fn_accept  =(fn_sock_accept_t) dlsym(RTLD_DEFAULT,"SocketAccept");
    fn_aes_init=(fn_aes_init_t)    dlsym(RTLD_DEFAULT,"AES_CTR_Init");
    fn_aes_upd =(fn_aes_upd_t)     dlsym(RTLD_DEFAULT,"AES_CTR_Update");
    fn_aes_fin =(fn_aes_fin_t)     dlsym(RTLD_DEFAULT,"AES_CTR_Final");
    alt_syms_ok = (fn_derive&&fn_sockopen&&fn_accept)?1:0;
    if(!alt_syms_ok) lg("alt: symbol resolve FAILED derive=%p sockopen=%p accept=%p",
                        (void*)fn_derive,(void*)fn_sockopen,(void*)fn_accept);
    return alt_syms_ok;
}

/* one receiver at a time is enough for this milestone */
static volatile int  alt_stop   = 0;
static volatile int  alt_listen = -1;
static volatile int  alt_busy   = 0;
static uint8_t alt_key[16], alt_iv[16];



static void alt_nv_open(void);
static void alt_nv_close(void);
static void alt_nv_configure(void);
static void alt_nv_open(void);
static void alt_nv_configure(void);
static void alt_nv_close(void);
extern volatile int alt_feed_gate;
extern volatile int alt_stock_live;
extern volatile int alt_force_rebuild;
extern volatile int alt_pts_reset;
extern volatile int alt_idr_req;
static void nvp_probe(void);
static void alt_zoom_tick(void);
static void bnr_collect(void);
extern volatile time_t alt_last_rx;
volatile time_t alt_last_rx;
extern volatile int alt_showui_req;
extern volatile int alt_va_req;
static int alt_send_viewarea(const char*);
static int alt_send_nightmode(int,const char*);
volatile int alt_va_req;
volatile int alt_showui_req;
static int alt_send_cluster_idr(const char*);
extern void *alt_session;
static int alt_send_showui(const char*);
static volatile int alt_showui_sent;
static volatile int alt_showui_acked;
static char alt_showui_last[256];
static void alt_idr_healthy(void);
static int alt_idr_permit(int,const char*);
enum { ALT_IDR_UI=1, ALT_IDR_RECOVERY=2, ALT_IDR_REBUILD=3 };
static volatile int alt_showui_acked;
static char alt_showui_last[256];
static int alt_keep_alive(void);
extern volatile int alt_in_decode;
extern volatile int alt_reopen_req;
extern volatile int alt_release_req;
static void alt_ctx_claim(void);
static void alt_ctx_release(void);
void alt_ctx_release_why(const char*);
static void alt_run_pending_stop(const char*);
static void alt_stand_down_full(void);
static void kd_term_settle(void);
static void alt_ctx_recover_stale(void);
/* stall watchdog state, defined with the context code further down */
extern volatile time_t alt_last_ok;
extern volatile int    alt_stalled;

/* cluster-NvSS state, declared early because the 111 receiver thread sits above
 * the implementation block yet both enables feeding and calls decode() */
#define ALT_LAYER      58
#define ALT_OUTPUT_DEV 1
typedef void* (*fn_ctor_t)(void*);
typedef int   (*fn_init_t)(void*, void*);
typedef int   (*fn_start_t)(void*);
typedef int   (*fn_stop_t)(void*);
typedef void* (*fn_dtor_t)(void*);
typedef int   (*fn_vis_t)(void*, unsigned char);
typedef int   (*fn_cfg7_t)(void*,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned);
typedef int   (*fn_setattr_t)(void*,void*);
typedef int   (*fn_dec5_t)(void*,unsigned char*,unsigned,unsigned long long,unsigned char);
static fn_ctor_t    nv_ctor;
static fn_init_t    nv_init;
static fn_start_t   nv_start;
static fn_stop_t    nv_stop;
static fn_dtor_t    nv_dtor;
static fn_vis_t     nv_vis;
static fn_cfg7_t    nv_configure;
static fn_setattr_t nv_setattribs;
static fn_dec5_t    nv_decode;
static void *alt_stock_obj;
static void *alt_nv_obj;
static volatile pthread_t alt_nv_claim_thr;   /* OUR start() thread, 0 = none */

/* ---- Annex-B conversion + dump -------------------------------------------
 * avcC (opcode 1): configurationVersion, profile, compat, level,
 *   [4] 0xFC|lengthSizeMinusOne, [5] 0xE0|numSPS, then u16-len SPS..., u8 numPPS,
 *   then u16-len PPS...  Each parameter set is emitted with a 4-byte start code.
 * video (opcode 0): sequence of [lengthSize BE length][NALU]; each length field
 *   is replaced by a 4-byte start code. */
static const unsigned char ALT_SC[4] = {0,0,0,1};
static FILE *alt_dump;
static unsigned alt_dumped;
static int alt_lensize = 4;
/* Annex-B staging for the cluster decoder: one access unit at a time */
static unsigned char *alt_au;
static unsigned alt_au_len, alt_au_cap;
static int alt_au_collect;

static void alt_au_reset(void){ alt_au_len=0; }
static void alt_au_put(const unsigned char*p,unsigned n){
    if(!alt_au_collect||!n) return;
    if(alt_au_len+n>alt_au_cap){
        unsigned nc=(alt_au_len+n)*2u+4096u;
        unsigned char*nb=(unsigned char*)realloc(alt_au,nc);
        if(!nb){ alt_au_collect=0; return; }
        alt_au=nb; alt_au_cap=nc;
    }
    memcpy(alt_au+alt_au_len,p,n); alt_au_len+=n;
}

static void alt_dump_open(void){
    if(alt_dump) return;
    alt_dump=fopen(DUMP_PATH,"wb");
    alt_dumped=0;
    lg("alt: dump %s %s",DUMP_PATH,alt_dump?"opened":"FAILED");
}
static void alt_dump_write(const unsigned char*p,unsigned n){
    alt_au_put(p,n);
    if(!alt_dump||!n) return;
    if(alt_dumped>=DUMP_CAP) return;
    if(alt_dumped+n>DUMP_CAP) n=DUMP_CAP-alt_dumped;
    if(fwrite(p,1,n,alt_dump)!=n){ lg("alt: dump write short, closing"); fclose(alt_dump); alt_dump=0; return; }
    alt_dumped+=n;
    if(alt_dumped>=DUMP_CAP){ fflush(alt_dump); lg("alt: dump cap %u reached, still decrypting",DUMP_CAP); }
}
static void alt_dump_close(void){
    if(!alt_dump) return;
    fflush(alt_dump); fclose(alt_dump); alt_dump=0;
    lg("alt: dump closed, %u bytes -> %s",alt_dumped,DUMP_PATH);
}

/* parse avcC, emit SPS/PPS as Annex-B, remember lengthSize */
static unsigned char alt_avcc_buf[512];
static unsigned      alt_avcc_len;

static void alt_emit_avcc(const unsigned char*b,unsigned n){
    if(n<7){ lg("alt: avcC too short (%u)",n); return; }
    if(n<=sizeof alt_avcc_buf && b!=alt_avcc_buf){
        /* v57: a NEW codec config mid-stream means the phone re-configured its
         * encoder - measured on the car when a route starts in Apple Maps: four
         * fresh avcC in ten seconds, while our NvSS decoder stayed configured
         * for the first one and silently produced nothing. Every feed still
         * returned 0, which is why this looked like a protocol problem for
         * hours. Waze never does it, which is why Waze never broke.
         *
         * A decoder cannot be re-parameterised in place here, so rebuild it;
         * the rebuild path re-primes with this very avcC and asks for an IDR. */
        if(alt_avcc_len && (alt_avcc_len!=n || memcmp(alt_avcc_buf,b,n))){
            lg("*** alt: NEW avcC from the phone (%u -> %u bytes) — the stream was "
               "re-configured, rebuilding our decoder ***",alt_avcc_len,n);
            alt_force_rebuild=1;
        }
        memcpy(alt_avcc_buf,b,n); alt_avcc_len=n;   /* v45: for a re-prime */
    }
    alt_lensize=(b[4]&3)+1;
    unsigned off=5, i;
    unsigned nsps=b[off++]&0x1F;
    lg("alt: avcC profile=%u level=%u lengthSize=%d numSPS=%u",b[1],b[3],alt_lensize,nsps);
    for(i=0;i<nsps && off+2<=n;i++){
        unsigned l=((unsigned)b[off]<<8)|b[off+1]; off+=2;
        if(off+l>n) return;
        alt_dump_write(ALT_SC,4); alt_dump_write(b+off,l); off+=l;
    }
    if(off>=n) return;
    unsigned npps=b[off++];
    lg("alt: avcC numPPS=%u",npps);
    for(i=0;i<npps && off+2<=n;i++){
        unsigned l=((unsigned)b[off]<<8)|b[off+1]; off+=2;
        if(off+l>n) return;
        alt_dump_write(ALT_SC,4); alt_dump_write(b+off,l); off+=l;
    }
}

/* AVCC length-prefixed -> Annex-B start codes */
static int alt_emit_avcc_au(const unsigned char*b,unsigned n){
    unsigned off=0, nalus=0;
    int ls=alt_lensize;
    while(off+(unsigned)ls<=n){
        unsigned l=0,k;
        for(k=0;k<(unsigned)ls;k++) l=(l<<8)|b[off+k];
        off+=ls;
        if(l==0||off+l>n) return -1;
        alt_dump_write(ALT_SC,4); alt_dump_write(b+off,l);
        off+=l; nalus++;
    }
    return (off==n && nalus)?0:-1;
}

/* The socket from SocketAccept is non-blocking (v13 measured EAGAIN on the very
 * first recv). Wait for readability instead of mistaking EAGAIN for EOF, and keep
 * the 1 s tick so alt_stop is still observed promptly. */
static int alt_wait_readable(int fd,int secs){
    fd_set rf; struct timeval tv;
    FD_ZERO(&rf); FD_SET(fd,&rf);
    tv.tv_sec=secs; tv.tv_usec=0;
    return select(fd+1,&rf,0,0,&tv);
}

/* 0 = n bytes read, -1 = peer closed / fatal / stopped */
static int alt_read_full(int fd,unsigned char*buf,unsigned n,const char*what){
    unsigned off=0;
    while(off<n){
        if(alt_stop) return -1;
        int r=recv(fd,buf+off,n-off,0);
        if(r>0){ off+=r; continue; }
        if(r==0){ lg("alt: peer closed during %s (%u/%u)",what,off,n); return -1; }
        if(errno==EINTR) continue;
        if(errno==EAGAIN||errno==EWOULDBLOCK){
            int s=alt_wait_readable(fd,1);
            if(s<0&&errno!=EINTR){ lg("alt: select failed errno=%d",errno); return -1; }
            continue;
        }
        lg("alt: recv failed during %s errno=%d",what,errno);
        return -1;
    }
    return 0;
}

static void *alt_thread(void *arg){
    int lsock=(int)(long)arg, fd=-1;
    unsigned long long frames=0, bytes=0;
    unsigned char *body=0; unsigned bodycap=0;
    unsigned char hdr[ALT_HDR_SIZE];
    uint8_t aesctx[512] __attribute__((aligned(16)));
    int aes_ready=0, bad_au=0;
    lg("alt: receiver thread up, listen=%d",lsock);
    alt_showui_acked=0; alt_showui_last[0]=0; alt_showui_sent=0;   /* v64: new stream */
    while(!alt_stop){
        fd=-1;
        if(fn_accept(lsock,1,&fd,0)==0 && fd>=0) break;
    }
    if(fd<0||alt_stop){ lg("alt: no connection (stop=%d)",alt_stop); goto done; }
    lg("*** alt: 111 CONNECTION ACCEPTED fd=%d ***",fd);
    if(inject_level()>=5){
        alt_nv_open();
        if(inject_level()>=6) alt_nv_configure();
        if(inject_level()>=7 && alt_nv_obj && nv_decode){
            alt_au_collect=1;
            lg("*** alt-nv: frame feeding ENABLED (level 7) ***");
        } else if(inject_level()>=7)
            lg("alt-nv: feeding NOT enabled (obj=%p decode=%p)",alt_nv_obj,(void*)nv_decode);
    }
    if(fn_aes_init&&fn_aes_upd&&fn_aes_init(aesctx,alt_key,alt_iv)==0){ aes_ready=1; lg("alt: AES-CTR context ready"); }
    else lg("alt: AES-CTR init FAILED — bodies stay encrypted");
    alt_dump_open();
    while(!alt_stop){
        if(alt_read_full(fd,hdr,ALT_HDR_SIZE,"header")!=0) goto eof;
        unsigned bsz = (unsigned)hdr[0] | ((unsigned)hdr[1]<<8)
                     | ((unsigned)hdr[2]<<16) | ((unsigned)hdr[3]<<24);
        unsigned op  = hdr[4];
        if(bsz>ALT_MAX_BODY){ lg("alt: body too big %u, abort",bsz); goto eof; }
        if(bsz>bodycap){
            unsigned char *nb=(unsigned char*)realloc(body,bsz);
            if(!nb){ lg("alt: oom body=%u",bsz); goto eof; }
            body=nb; bodycap=bsz;
        }
        if(bsz && alt_read_full(fd,body,bsz,"body")!=0) goto eof;
        frames++; bytes+=ALT_HDR_SIZE+bsz;
        /* v66: only a real access unit (op 0) proves pictures are arriving.
         * v65 stamped every packet, and the phone keeps sending config (op 1,
         * after each keyframe request) and other housekeeping packets while a
         * static turn card is on screen - the watchdog took those for "frames
         * arriving but not decoding" and released the cluster anyway. */
        if(op==0) alt_last_rx=time(0);
        else if(op!=1){
            static int seen[256], logged;
            if(!seen[op&0xff] && logged<16){ seen[op&0xff]=1; logged++;
                lg("alt: packet op=%u body=%u on the 111 channel (not a frame)",op,bsz); }
        }
        if(op==1){                      /* avcC config, plaintext */
            alt_emit_avcc(body,bsz);
        }else if(op==0){                /* encrypted AVCC access unit */
            if(aes_ready){
                int rc=fn_aes_upd(aesctx,body,bsz,body);
                if(rc!=0){ lg("alt: AES-CTR update rc=%d at frame %llu — stopping",rc,frames); goto eof; }
                if(alt_emit_avcc_au(body,bsz)!=0 && bad_au<5){
                    bad_au++;
                    lg("alt: AU #%llu not valid AVCC after decrypt (body=%u ls=%d first=%02x%02x%02x%02x)",
                       frames,bsz,alt_lensize,body[0],body[1],body[2],body[3]);
                }
            }
        }
        if(alt_feed_gate){
            /* Drain and decrypt as usual, but do not go anywhere near NvSS:
             * the shared libKD state has no owner. The watchdog hands the
             * cluster back to the Porsche map meanwhile. */
            if(alt_reopen_req && inject_level()>=5){
                alt_reopen_req=0;
                lg("alt: stock stream is back — rebuilding our cluster stream");
                /* Safe here, and only here: the stock stream owns the shared
                 * NvSS/libKD state, and we are on our own thread, not inside
                 * any stock call. */
                alt_nv_close();
                alt_nv_open();
                if(alt_nv_obj){
                    if(inject_level()>=6) alt_nv_configure();
                    if(inject_level()>=7 && nv_decode){
                        alt_last_ok=0; alt_stalled=0; alt_au_collect=1;
                    }
                    alt_feed_gate=0;
                    /* v45: a fresh decoder needs the parameter sets again. */
                    if(alt_avcc_len){
                        alt_emit_avcc(alt_avcc_buf,alt_avcc_len);
                        lg("alt: re-primed the new decoder with cached avcC "
                           "(%u bytes) — picture returns at the next IDR",alt_avcc_len);
                    } else lg("alt: no cached avcC to re-prime with");
                    lg("alt: rebuilt, feeding resumed");
                } else lg("alt: rebuild FAILED — cluster keeps the stock map");
            }
        }
        else if(alt_force_rebuild && alt_nv_obj){
            alt_force_rebuild=0;
            lg("alt: forced rebuild — closing and reopening our cluster stream");
            alt_nv_close();
            alt_nv_open();
            if(alt_nv_obj){
                if(inject_level()>=6) alt_nv_configure();
                alt_last_ok=0; alt_stalled=0; alt_au_collect=1; alt_pts_reset=1;
                if(alt_avcc_len){
                    alt_emit_avcc(alt_avcc_buf,alt_avcc_len);
                    lg("alt: re-primed after the forced rebuild (%u bytes avcC)",alt_avcc_len);
                }
                alt_idr_req=ALT_IDR_REBUILD;   /* and ask the phone for a fresh IDR */
                lg("alt: forced rebuild done");
            } else lg("alt: forced rebuild FAILED — cluster keeps the stock map");
            alt_au_reset();
            continue;
        }
        else if(alt_au_collect && alt_au_len && nv_decode && alt_nv_obj){
            static unsigned long long fed=0, pts=0, pts_base=0;
            /* Drop frames before they reach the decoder. Keyframes cannot be
             * dropped or the picture never recovers, and with avcC we cannot
             * tell cheaply, so only drop small (clearly inter-coded) AUs. */
            if(alt_skip && alt_au_len < 8000 && (frames % (unsigned)(alt_skip+1))){
                alt_au_reset();
                continue;
            }
            int dr;
            alt_in_decode=1;
            dr = alt_feed_gate ? 0 : nv_decode(alt_nv_obj,alt_au,alt_au_len,pts,0);
            alt_in_decode=0;
            if(alt_feed_gate){ alt_au_reset(); continue; }
            /* The step MUST match the rate the phone actually sends, or the
             * decoder is handed timestamps for a slower clip and plays it
             * back at that speed. Hardcoded 33333 (30 fps) against an
             * announced 15 fps is exactly why the map moved at half speed. */
            /* v48: the presentation clock must come from the clock, not from
             * a constant. Counting 1000000/fps per frame assumes the phone
             * sends at exactly the announced rate; measured on the car it
             * sends ~1% slower, so the timestamps ran ~2 s ahead of real time
             * after three minutes. The picture froze while every feed still
             * returned 0 - the decoder was waiting for a presentation time
             * that had drifted into the future.
             *
             * Now the timestamp is simply how long this stream has been
             * running, so it cannot drift. alt_ptsmode=0 restores the old
             * fixed step for comparison. */
            if(alt_pts_reset){ alt_pts_reset=0; pts_base=0; pts=0; }
            if(alt_ptsmode){
                struct timespec ts;
                if(clock_gettime(CLOCK_MONOTONIC,&ts)==0){
                    unsigned long long now=(unsigned long long)ts.tv_sec*1000000ULL
                                          +(unsigned long long)(ts.tv_nsec/1000);
                    if(!pts_base) pts_base=now;
                    unsigned long long el=now-pts_base;
                    /* never go backwards, and never sit on the same stamp */
                    if(el<=pts) pts += 1000;
                    else pts = el;
                } else pts += (unsigned long long)(1000000/(alt_fps>0?alt_fps:30));
            } else
            pts += (unsigned long long)(1000000/(alt_fps>0?alt_fps:30));
            fed++;
            if(fed<=5 || (fed%300)==0)
                lg("alt-nv feed #%llu len=%u pts=%llu -> %d",fed,alt_au_len,pts,dr);
            if(dr!=0 && fed<=5) lg("alt-nv feed ERROR rc=%d — stopping feed",dr);
            if(dr!=0){ alt_au_collect=0; alt_ctx_release_why("decode error"); }
            else {
                alt_last_ok=time(0);
                if(fed>=10) {
                    /* claim on the 10th frame as before; if the watchdog had
                     * released us because of a stall, re-claim once frames are
                     * genuinely flowing again. */
                    if(alt_stalled){
                        alt_stalled=0;
                        lg("alt-watchdog: frames are back — re-claiming the cluster");
                    }
                    alt_idr_healthy();
                    if(alt_stock_live) alt_ctx_claim();
                    if(!alt_showui_sent) alt_send_showui("first frames");
                }
            }
        }
        alt_au_reset();
        if(frames<=5 || (frames%300)==0)
            lg("alt: frame #%llu op=%u body=%u total=%llu dumped=%u",frames,op,bsz,bytes,alt_dumped);
    }
eof:
    if(aes_ready&&fn_aes_fin) fn_aes_fin(aesctx);
    alt_au_collect=0;
    alt_ctx_release();          /* stock map back BEFORE our plane disappears */
    alt_run_pending_stop("our stream ended");
    if(alt_au){ free(alt_au); alt_au=0; alt_au_cap=0; alt_au_len=0; }
    /* Only close if we never stood down. If we did, the stock side is already
     * tearing down and touching NvSS here is what crashes. */
    if(!alt_feed_gate) alt_nv_close();
    else { lg("alt: leaving our stream open at session end (stood down earlier)"); alt_nv_obj=0; }
    alt_dump_close();
    lg("alt: stream ended frames=%llu bytes=%llu errno=%d",frames,bytes,errno);
done:
    if(body) free(body);
    if(fd>=0) close(fd);
    if(lsock>=0) close(lsock);
    alt_listen=-1; alt_busy=0;
    lg("alt: receiver thread exit");
    return 0;
}

/* find the stream descriptor with type==111 in request["streams"] */
/* v62: match OUR stream by the display uuid, not only by type 111.
 *
 * Bisection proved that declaring a type-111 display is itself what breaks an
 * Apple Maps route on this firmware - every optional key stripped out and it
 * still broke; with type 110 the route is fine. So the question became whether
 * iOS will stream video to a second display that it does not consider an
 * instrument cluster. It offers streams by display uuid, so look for ours. */
static const char *cfs(const void *s,char *buf,int n);
static const char *alt_stream_uuid(void *d,char *buf,int n){
    static const char *keys[]={"uuid","displayUUID","uid",0};
    int i; buf[0]=0;
    for(i=0;keys[i];i++){
        void *k=cf_str(0,keys[i],CFENC_UTF8);
        void *v=k?cf_getval(d,k):0;
        if(v) cfs(v,buf,n);
        if(k)cf_rel(k);
        if(buf[0]) return buf;
    }
    return buf;
}

static void *alt_find_111(void *request){
    void *ks=cf_str(0,"streams",CFENC_UTF8), *kt=cf_str(0,"type",CFENC_UTF8), *hit=0;
    if(ks&&kt){
        void *arr=cf_getval(request,ks);
        long n=(arr&&cf_arrcnt)?cf_arrcnt(arr):0, i;
        for(i=0;i<n;i++){
            void *d=cf_arrget?cf_arrget(arr,i):0; if(!d) continue;
            int e=0; long long t=cf_geti64?(long long)cf_geti64(d,kt,&e):-1;
            char ub[80]; const char *u=alt_stream_uuid(d,ub,sizeof ub);
            lg("SETUP stream type=%lld uuid='%s'",t,u);
            if(t==ALT_STREAM_TYPE){ hit=d; lg("  -> ours by type"); break; }
            if(u[0] && !strcmp(u,CLUSTER_UUID)){ hit=d; lg("  -> OURS BY UUID (type %lld)",t); break; }
        }
    }
    if(ks)cf_rel(ks); if(kt)cf_rel(kt);
    return hit;
}

/* append desc to resp["streams"] (replica of stock _AddResponseStream) */
static int alt_add_response_stream(void *resp, void *desc){
    void *k=cf_str(0,"streams",CFENC_UTF8); int ok=0;
    if(!k) return -1;
    void *arr=cf_getval(resp,k);
    if(arr){ cf_arrapp(arr,desc); ok=1; }
    else{
        arr=cf_arrm(0,0,arr_cb);
        if(arr){ cf_arrapp(arr,desc); cf_dictset(resp,k,arr); cf_rel(arr); ok=1; }
    }
    cf_rel(k);
    return ok?0:-1;
}

/* Returns 0 on success (dataPort published), negative on failure. */
static int alt_setup(void *session, void *desc, void *resp){
    if(!alt_syms()) return -1;
    if(!session||!desc||!resp) return -2;
    if(alt_busy){ lg("alt: receiver already busy, refusing second setup"); return -3; }

    long long connID=0;
    { void *k=cf_str(0,"streamConnectionID",CFENC_UTF8);
      if(k){ int e=0; connID=cf_geti64?(long long)cf_geti64(desc,k,&e):0; cf_rel(k);} }
    if(!connID){ lg("alt: streamConnectionID missing"); return -4; }
    lg("alt: connID=%lld",connID);

    fn_derive((const uint8_t*)((char*)session+OFF_AESKEY),16,(uint64_t)connID,alt_key,alt_iv);
    lg("alt: aes key derived (from session+%d)",OFF_AESKEY);

    int family=*(uint8_t*)((char*)session+OFF_FAMILY);
    void *server=*(void**)((char*)session+OFF_SERVER);
    int qos = (server && fn_setqos && !*(uint8_t*)((char*)server+SVR_OFF_QOSDISABLED));

    /* pf on carplay0 default-denies inbound; only these TCP ports are passed.
     * 6030 is stock stream 110 — never take it. Ordered by preference. */
    static const int ALLOWED[] = { 6100, 6200, 7100, 6001, 6000, 7001, 7000, 5010 };
    const int nallowed = (int)(sizeof(ALLOWED)/sizeof(ALLOWED[0]));
    int port=0, sock=-1, err=-1, i;
    for(i=0;i<nallowed;i++){
        port=0; sock=-1;
        err=fn_sockopen(family,1/*SOCK_STREAM*/,6/*IPPROTO_TCP*/,-ALLOWED[i],&port,-180224,&sock);
        lg("alt: try pf-allowed port %d -> err=%d got=%d sock=%d",ALLOWED[i],err,port,sock);
        if(err==0 && sock>=0 && port==ALLOWED[i]) break;   /* exact match only */
        if(sock>=0) close(sock);
        sock=-1; port=0;
    }
    if(i>=nallowed || sock<0 || port<=0){
        lg("alt: NO pf-allowed port available — refusing to publish a dead dataPort");
        return -5;
    }
    lg("alt: listener on pf-allowed port=%d sock=%d family=%d qos=%d",port,sock,family,qos);
    if(qos) fn_setqos(sock,12);

    void *rdesc=cf_dictm(0,0,dict_keycb,dict_valcb);
    if(!rdesc){ close(sock); return -6; }
    if(set_i64(rdesc,"type",ALT_STREAM_TYPE)||set_i64(rdesc,"dataPort",port)){
        cf_rel(rdesc); close(sock); return -7; }

    alt_stop=0; alt_busy=1; alt_listen=sock;
    pthread_t th; pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at,PTHREAD_CREATE_DETACHED);
    if(pthread_create(&th,&at,alt_thread,(void*)(long)sock)!=0){
        pthread_attr_destroy(&at);
        lg("alt: pthread_create FAILED");
        alt_busy=0; alt_listen=-1; cf_rel(rdesc); close(sock); return -8;
    }
    pthread_attr_destroy(&at);

    if(alt_add_response_stream(resp,rdesc)!=0){
        lg("alt: add_response_stream FAILED");
        alt_stop=1; cf_rel(rdesc); return -9;
    }
    cf_rel(rdesc);
    lg("*** alt: 111 ANSWERED with dataPort=%d ***",port);
    return 0;
}

/* ===== THE REAL altScreen GATE (verified vs iOS 26.6 disasm, luka-dev):
 * phone proposes "features" in control-SETUP REQUEST, but reads the NEGOTIATED set
 * from the SETUP RESPONSE under "enabledFeatures" -> endpoint[+0x3E]=contains(altScreen).
 * Streams per display only if displays>=2 && +0x3E. /info extendedFeatures does NOT set it.
 * Stock 210 writes no response enabledFeatures -> altScreen never negotiates. We merge it here. */
__attribute__((visibility("default")))
int AirPlayReceiverSessionSetup(void *session, void *request, void **respOut, int a4){
    alt_session=session;
    static fn_sess_setup_t real=0;
    if(!real) real=(fn_sess_setup_t)dlsym(RTLD_NEXT,"AirPlayReceiverSessionSetup");
    if(!real){ lg("SETUP real NULL"); return -1; }
    int ret=real(session,request,respOut,a4);
    void*resp=(respOut&&*respOut)?*respOut:0;
    lg("SETUP ret=%d resp=%p",ret,resp);
    if(cf_init()!=1 || !request) return ret;
    int lvl=inject_level();
    if(lvl>0) alt_ctx_recover_stale();
    int isControl=0;
    { void*k=cf_str(0,"features",CFENC_UTF8); if(k){ isControl=(cf_getval(request,k)!=0); cf_rel(k);} }
    if(isControl && lvl>=3 && ret==0 && resp){
        void*kE=cf_str(0,"enabledFeatures",CFENC_UTF8);
        if(kE){
            void*cur=cf_getval(resp,kE); long curN=(cur&&cf_arrcnt)?cf_arrcnt(cur):-1;
            void*neg=cf_arrm(0,0,arr_cb);
            if(neg){
                for(long i=0;i<curN;i++){ void*e=cf_arrget?cf_arrget(cur,i):0; if(e)cf_arrapp(neg,e); }
                int ok=1;
                if(cf_arrappc){ ok=(cf_arrappc(neg,"altScreen",-1)==0 && cf_arrappc(neg,"viewAreas",-1)==0); }
                else { void*s=cf_str(0,"altScreen",CFENC_UTF8); if(s){cf_arrapp(neg,s);cf_rel(s);}else ok=0;
                       s=cf_str(0,"viewAreas",CFENC_UTF8); if(s){cf_arrapp(neg,s);cf_rel(s);}else ok=0; }
                if(ok){ cf_dictset(resp,kE,neg); lg("control SETUP: enabledFeatures MERGED (existing=%ld) + altScreen + viewAreas",curN); }
                else lg("control SETUP: enabledFeatures build FAILED");
                cf_rel(neg);
            }
            cf_rel(kE);
        }
    } else if(isControl) lg("control SETUP seen (level=%d ret=%d) - not negotiating",lvl,ret);
    /* log every stream type iOS offers in this SETUP; 111 = cluster accepted */
    { void*ks=cf_str(0,"streams",CFENC_UTF8); void*kt=cf_str(0,"type",CFENC_UTF8);
      if(ks&&kt){ void*arr=cf_getval(request,ks); long n=(arr&&cf_arrcnt)?cf_arrcnt(arr):0;
        for(long i=0;i<n;i++){ void*d=cf_arrget?cf_arrget(arr,i):0; if(!d)continue; int e=0; long long t=cf_geti64?(long long)cf_geti64(d,kt,&e):-1;
          lg("SETUP stream[%ld] type=%lld",i,t);
          if(t==111) lg("*** 111 STREAM OFFERED BY iOS *** advert+negotiation ACCEPTED"); } }
      if(ks)cf_rel(ks); if(kt)cf_rel(kt); }

    /* level 4: actually serve the 111 stream so the session can survive */
    if(lvl>=4 && ret==0 && resp){
        void *desc=alt_find_111(request);
        if(desc){
            int arc=alt_setup(session,desc,resp);
            lg("alt_setup -> %d",arc);
            /* never report HTTP success without a usable 111 dataPort */
            if(arc!=0) ret=-6700;
        }
    }
    return ret;
}
static void*real_ssc=0,*real_sss=0; static int n_ssc=0,n_sss=0;
__attribute__((visibility("default"))) void*ScreenStreamCreate(void){ void*a=__builtin_apply_args(); if(!real_ssc)real_ssc=dlsym(RTLD_NEXT,"ScreenStreamCreate"); lg("ScreenStreamCreate #%d",++n_ssc); if(fail_count()){ fail_write(0); lg("main CarPlay up — self-disarm counter cleared"); } void*r=__builtin_apply((void(*)())real_ssc,a,160); __builtin_return(r); }
__attribute__((visibility("default"))) void*ScreenStreamStart(void){ void*a=__builtin_apply_args(); if(!real_sss)real_sss=dlsym(RTLD_NEXT,"ScreenStreamStart"); lg("ScreenStreamStart #%d",++n_sss); void*r=__builtin_apply((void(*)())real_sss,a,160); __builtin_return(r); }

__attribute__((visibility("default"))) void*AirPlayCopyServerInfo(void*s,void*q,void*m,void*e){ static fn_copyinfo_t real=0; if(!real)real=(fn_copyinfo_t)dlsym(RTLD_NEXT,"AirPlayCopyServerInfo"); if(!real){lg("REAL_NULL");return 0;} void*info=real(s,q,m,e); lg("/info session=%p info=%p",s,info); if(info&&cf_init()==1)inject(info); return info; }
__attribute__((visibility("default")))
/* v63: record WHY a session is torn down. On an Apple Maps route the phone
 * itself sends TEARDOWN (`_requestProcessTearDown` in the firmware log), so the
 * reason code and the request contents are the phone's own statement of what
 * it did not like. Until now we only noted that it happened. */
static const char *alt_status_name(int st){
    switch(st){
        case 0:     return "kNoErr";
        case -6700: return "kUnknownErr";
        case -6705: return "kParamErr";
        case -6709: return "kStateErr";
        case -6714: return "kNotHandledErr";
        case -6722: return "kTimeoutErr";
        case -6727: return "kNotFoundErr";
        case -6735: return "kUnsupportedErr";
        case -6753: return "kConnectionErr";
        case -6762: return "kEndingErr";
        default:    return "?";
    }
}

int AirPlayReceiverSessionTearDown(void *session, void *request, int reason, void *outDone){
    static int (*real)(void*,void*,int,void*)=0;
    if(!real) real=(int(*)(void*,void*,int,void*))dlsym(RTLD_NEXT,"AirPlayReceiverSessionTearDown");
    lg("*** TEARDOWN: session=%p request=%p reason=%d (%s) — %s ***",
       session,request,reason,alt_status_name(reason),
       request?"phone asked for specific streams":"whole session");
    if(request && cf_init()==1 && cf_getval && cf_str){
        /* which streams the phone named, and any top-level keys it sent */
        static const char *keys[]={"streams","reason","error","status","type",0};
        int i;
        for(i=0;keys[i];i++){
            void *k=cf_str(0,keys[i],CFENC_UTF8);
            void *v=k?cf_getval(request,k):0;
            if(v){
                char vb[120];
                lg("TEARDOWN: request has '%s' = %p '%s'",keys[i],v,cfs(v,vb,sizeof vb));
            }
            if(k)cf_rel(k);
        }
    }
    int has111=0;
    if(request && cf_init()==1) has111 = (alt_find_111(request)!=0);
    /* NULL/absent request == full teardown; otherwise only stop for our own stream */
    if(!request || has111){
        /* Do this synchronously: dio exits before the receiver thread wakes. */
        alt_ctx_release();
        if(alt_busy){ lg("alt: teardown -> stopping receiver (req=%p has111=%d)",request,has111); alt_stop=1; }
    }
    return real?real(session,request,reason,outDone):0;
}

/* ===== second NvSS stream on the cluster (level 5) ======================== */

typedef void* (*fn_ctor_t)(void*);
typedef int   (*fn_init_t)(void*, void*);
typedef int   (*fn_start_t)(void*);
typedef int   (*fn_stop_t)(void*);
typedef void* (*fn_dtor_t)(void*);
typedef int   (*fn_vis_t)(void*, unsigned char);

static fn_init_t  nv_init;
static fn_stop_t  nv_stop;
static fn_vis_t   nv_vis;


static void *alt_nv_handle;     /* our own NvSS handle, for the Close interpose */

static int alt_nv_syms(void){
    if(nv_ctor&&nv_init&&nv_start) return 1;
    nv_ctor =(fn_ctor_t) dlsym(RTLD_DEFAULT,"_ZN3dio13NvssVideoImplC1Ev");
    nv_init =(fn_init_t) dlsym(RTLD_DEFAULT,"_ZN3dio13NvssVideoImpl10initializeERPFvvE");
    nv_start=(fn_start_t)dlsym(RTLD_DEFAULT,"_ZN3dio13NvssVideoImpl5startEv");
    nv_stop =(fn_stop_t) dlsym(RTLD_DEFAULT,"_ZN3dio13NvssVideoImpl4stopEv");
    nv_dtor =(fn_dtor_t) dlsym(RTLD_DEFAULT,"_ZN3dio13NvssVideoImplD1Ev");
    nv_vis  =(fn_vis_t)  dlsym(RTLD_DEFAULT,"_ZN3dio13NvssVideoImpl13setVisibilityEh");
    nv_configure =(fn_cfg7_t)   dlsym(RTLD_DEFAULT,"_ZN3dio13NvssVideoImpl9configureEjjjjjjj");
    nv_setattribs=(fn_setattr_t)dlsym(RTLD_DEFAULT,"NvSSVideoSetAttribs");
    nv_decode    =(fn_dec5_t)   dlsym(RTLD_DEFAULT,"_ZN3dio13NvssVideoImpl6decodeEPhjyb");
    if(!(nv_ctor&&nv_init&&nv_start)){
        lg("alt-nv: symbol resolve FAILED ctor=%p init=%p start=%p",
           (void*)nv_ctor,(void*)nv_init,(void*)nv_start);
        return 0;
    }
    lg("alt-nv: symbols ok ctor=%p init=%p start=%p stop=%p dtor=%p vis=%p",
       (void*)nv_ctor,(void*)nv_init,(void*)nv_start,(void*)nv_stop,(void*)nv_dtor,(void*)nv_vis);
    return 1;
}

static void alt_nv_open(void){
    static void (*cb)(void) = 0;
    void *cbref = &cb;
    if(alt_nv_obj){ lg("alt-nv: already open"); return; }
    if(!alt_nv_syms()) return;
    void *o=calloc(1,512);
    if(!o){ lg("alt-nv: calloc failed"); return; }
    nv_ctor(o);
    lg("alt-nv: constructed obj=%p vptr=%p handle=%p",o,*(void**)o,*(void**)((char*)o+4));
    int rc=nv_init(o,cbref);
    lg("alt-nv: initialize -> %d",rc);
    alt_nv_claim_thr=pthread_self();
    rc=nv_start(o);
    alt_nv_claim_thr=(pthread_t)0;
    void *h=*(void**)((char*)o+4);
    lg("*** alt-nv: start -> %d handle=%p (layer %d, outputDevice %d) ***",rc,h,ALT_LAYER,ALT_OUTPUT_DEV);
    if(rc!=0 || !h){
        lg("alt-nv: start failed, tearing the object down");
        if(nv_dtor) nv_dtor(o);
        free(o);
        return;
    }
    alt_nv_obj=o;
    alt_nv_handle=h;
}



/* ---- automatic cluster context switching --------------------------------- */
static int alt_ctx[3] = { 4, 76, 72 };     /* display, ours, stock */
static int alt_ctx_on;                      /* 1 = cluster currently points at us */

/* The receiver thread claims/releases, and from v29 the watchdog thread does
 * too, so the flag and the dmdt call need a lock of their own. */
static pthread_mutex_t alt_ctx_mx = PTHREAD_MUTEX_INITIALIZER;

/* Stall watchdog state. last_ok is seconds-since-boot of the last decode that
 * returned 0; 0 means "nothing decoded yet". */
#ifndef STALL_SEC
#define STALL_SEC 3
#endif
#ifndef SWITCH_MIN_GAP
#define SWITCH_MIN_GAP 5          /* never flap the cluster faster than this */
#endif
volatile time_t alt_last_ok;
volatile int    alt_stalled;               /* 1 = released because of a stall */

/* 1 = the stock main-screen stream is down, so the NvSS/libKD process state
 * has no owner and must not be touched. See the header: the fault at
 * libKD+0xf1f4 is a NULL deref of exactly that shared state. */
volatile int    alt_feed_gate;
/* v45: the stock CarPlay screen stream is live. Our cluster stream may keep
 * decoding while it is down, but it must NOT hold the cluster: the owner wants
 * the Porsche map back the moment CarPlay leaves the foreground. */
volatile int    alt_stock_live=1;
/* v47: set by the watchdog when /tmp/alt_rebuild appears; acted on by the
 * receiver thread, which is the only thread allowed to touch our NvSS. */
volatile int    alt_force_rebuild;
volatile int    alt_pts_reset;
/* 1 while the receiver thread is inside nv_decode. The gate alone is not
 * enough: ScreenStreamStop runs on a dio thread and could otherwise free our
 * object while the receiver is still in the call. */
volatile int    alt_in_decode;
/* set by the stock NvSSVideoOpen, acted on by the receiver thread */
volatile int    alt_reopen_req;
/* v41: the dmdt call cannot be made from inside the stock stop path - it
 * returned rc=-1 there, which is why the Porsche map did not come back. Ask
 * the watchdog thread to do it instead. */
volatile int    alt_release_req;
static time_t          alt_last_switch;

static void alt_ctx_load(void){
    char buf[64]; int n, v[3];
    FILE*f=cfg_open("alt_ctx");
    if(!f) return;
    n=(int)fread(buf,1,sizeof(buf)-1,f); fclose(f);
    if(n<=0) return; buf[n]=0;
    if(sscanf(buf,"%d %d %d",&v[0],&v[1],&v[2])==3){
        alt_ctx[0]=v[0]; alt_ctx[1]=v[1]; alt_ctx[2]=v[2];
        lg("alt-ctx: display=%d ours=%d stock=%d (from file)",v[0],v[1],v[2]);
    }
}

static void alt_ctx_switch(int ctx,const char*why){
    char cmd[160];
    snprintf(cmd,sizeof cmd,
        "IPL_CONFIG_DIR=/etc/eso/production /eso/bin/apps/dmdt sc %d %d >/dev/null 2>&1",
        alt_ctx[0],ctx);
    int rc=system(cmd);
    lg("*** alt-ctx: display %d -> context %d (%s) rc=%d ***",alt_ctx[0],ctx,why,rc);
}

static void alt_ctx_claim(void){
    pthread_mutex_lock(&alt_ctx_mx);
    if(alt_ctx_on){ pthread_mutex_unlock(&alt_ctx_mx); return; }
    { time_t now=time(0);
      if(alt_last_switch && now-alt_last_switch < SWITCH_MIN_GAP){
          pthread_mutex_unlock(&alt_ctx_mx); return; }
      alt_last_switch=now; }
    alt_ctx_on=1;
    /* Marker first: if we are SIGKILLed after the switch, the next session
     * finds this and puts the cluster back. Written before the switch so the
     * marker can never be missing while the cluster is ours. */
    { FILE*f=fopen(CLAIM_FILE,"w"); if(f){ fprintf(f,"%d\n",(int)getpid()); fclose(f); } }
    alt_ctx_switch(alt_ctx[1],"carplay stream live");
    pthread_mutex_unlock(&alt_ctx_mx);
}

void alt_ctx_release_why(const char*why){
    pthread_mutex_lock(&alt_ctx_mx);
    if(!alt_ctx_on){ pthread_mutex_unlock(&alt_ctx_mx); return; }
    alt_ctx_on=0;
    alt_last_switch=time(0);
    alt_ctx_switch(alt_ctx[2],why);
    unlink(CLAIM_FILE);
    pthread_mutex_unlock(&alt_ctx_mx);
}
static void alt_ctx_release(void){ alt_ctx_release_why("carplay gone"); }

/* Recovery for the one case the destructor cannot cover: dio_manager killed
 * outright while the cluster pointed at us, leaving the driver looking at a
 * dead context. Runs at the first SETUP of the next session, not in the
 * constructor — system() from a constructor runs before the process is fully
 * up. A PCM reboot also clears it, because the HMI reprograms display 4 and
 * the marker lives on the ramdisk. UNTESTED on the car: provoking it means
 * killing dio, which has already damaged the iAP2 session once. */
static int alt_stale_checked;
static void alt_ctx_recover_stale(void){
    if(alt_stale_checked) return;
    alt_stale_checked=1;
    FILE*f=fopen(CLAIM_FILE,"r");
    if(!f) return;
    fclose(f);
    if(alt_ctx_on) return;            /* ours, this session - not stale */
    lg("*** stale claim marker found — previous session died holding the "
       "cluster. Restoring stock context. ***");
    alt_ctx_switch(alt_ctx[2],"stale claim recovery");
    unlink(CLAIM_FILE);
}

/* ---- live geometry tuning ------------------------------------------------
 * /tmp/alt_geom : "dispW dispH srcW srcH dstX dstY dstW dstH"
 * Missing or unparsable -> the compiled defaults below. */
/* v46: the announced stream size (CLUSTER_W/H) and the physical panel
 * (PANEL_W/H) are no longer the same thing. iOS clamps the pixel density it
 * derives from widthPhysical/heightPhysical - 90x54 mm, 60x36 and even 30x18
 * all produced an identical map - so the only way left to get more map into
 * the frame is to ask the phone to DRAW more pixels and let the NvSS scaler
 * shrink them onto the 800x480 panel.
 *
 * disp and dst are the panel; src is what the phone sends. */
#ifndef PANEL_W
#define PANEL_W CLUSTER_W
#endif
#ifndef PANEL_H
#define PANEL_H CLUSTER_H
#endif
static int  alt_g[8] = { PANEL_W, PANEL_H, CLUSTER_W, CLUSTER_H, 0, 0, PANEL_W, PANEL_H };
static char alt_g_last[128];

static int alt_geom_load(void){           /* 1 if changed */
    char buf[128]; int n=0;
    FILE*f=fopen("/tmp/alt_geom","r");
    if(f){ n=(int)fread(buf,1,sizeof(buf)-1,f); fclose(f); }
    if(n<=0) buf[0]=0; else buf[n]=0;
    if(strcmp(buf,alt_g_last)==0) return 0;
    strncpy(alt_g_last,buf,sizeof(alt_g_last)-1); alt_g_last[sizeof(alt_g_last)-1]=0;
    if(!buf[0]) return 1;                 /* file removed -> fall back to defaults */
    int v[8], got=sscanf(buf,"%d %d %d %d %d %d %d %d",
                         &v[0],&v[1],&v[2],&v[3],&v[4],&v[5],&v[6],&v[7]);
    if(got==8){ int i; for(i=0;i<8;i++) alt_g[i]=v[i]; }
    else lg("alt-geom: need 8 numbers, got %d — ignoring",got);
    return 1;
}

static void alt_geom_apply(const char*why){
    void *o=alt_nv_obj; if(!o||!nv_setattribs) return;
    void *h=*(void**)((char*)o+4); if(!h) return;
    unsigned blk[16]; float one=1.0f;
    memset(blk,0,sizeof blk);
    blk[0]=(unsigned)alt_g[0]; blk[1]=(unsigned)alt_g[1];   /* display */
    blk[2]=1;                                                /* enable  */
    blk[5]=(unsigned)alt_g[2]; blk[6]=(unsigned)alt_g[3];    /* source  */
    blk[7]=(unsigned)alt_g[4]; blk[8]=(unsigned)alt_g[5];    /* dst x,y */
    blk[9]=(unsigned)alt_g[6]; blk[10]=(unsigned)alt_g[7];   /* dst w,h */
    memcpy(&blk[13],&one,4); memcpy(&blk[14],&one,4);
    int rc=nv_setattribs(h,blk);
    lg("alt-geom [%s]: disp=%dx%d src=%dx%d dst=%d,%d %dx%d -> %d",why,
       alt_g[0],alt_g[1],alt_g[2],alt_g[3],alt_g[4],alt_g[5],alt_g[6],alt_g[7],rc);
}

/* A frozen map in front of a driver is worse than no map: if nothing decodes
 * for STALL_SEC while we hold the cluster, hand it back to the stock Porsche
 * map. Correct regardless of what the underlying cause turns out to be. */
static int alt_helpers_up;         /* geometry tuner + watchdog started once */

static void *alt_watchdog_thread(void *a){
    (void)a;
    lg("alt-watchdog: up (stall=%ds)",STALL_SEC);
    while(!alt_stop){
        sleep(1);
        if(alt_release_req){
            alt_release_req=0;
            lg("alt-watchdog: performing the deferred cluster release");
            alt_ctx_release_why("stock stream stopped");
        }
        kd_term_settle();                 /* v42: pay back a held kdTerminateNV */
        nvp_probe();                      /* v68: NvMedia surface probe, on request */
        alt_zoom_tick();                  /* v74: cluster map zoom, one step per tick */
        bnr_collect();                    /* v69: banner samples, on request */
        if(alt_showui_req){ alt_showui_req=0; alt_send_showui("queued from suggestUI"); }
        /* v71: send showUI now with the current /tmp/alt_scene, for fast URL
         * experiments - the phone only re-suggests around route events.
         *   echo 1 > /tmp/alt_showui_now */
        { FILE *tf=fopen("/tmp/alt_showui_now","r");
          if(tf){ fclose(tf); remove("/tmp/alt_showui_now");
                  alt_showui_acked=0; alt_send_showui("manual trigger"); } }
        if(alt_va_req){ alt_va_req=0;
            alt_send_viewarea("after showUI");
            alt_send_nightmode(0,"after showUI"); }
        if(alt_idr_req){ int k=alt_idr_req; alt_idr_req=0;
            if(alt_idr_permit(k==ALT_IDR_REBUILD?ALT_IDR_REBUILD:ALT_IDR_UI,"scene change"))
                alt_send_cluster_idr(k==ALT_IDR_REBUILD?"rebuild":"scene change"); }
        /* v47: manual recovery. The decoder can wedge while still ACCEPTING
         * AUs - observed on the car: feeds returned 0 for minutes, IDR-sized
         * AUs among them, and the picture stayed frozen. rc=0 means the AU was
         * taken, not that anything was drawn, so neither the feed path nor the
         * stall watchdog can see it. Until there is a real liveness signal,
         * give the driver a way out that does not involve the cable:
         *     echo 1 > /tmp/alt_rebuild
         */
        { FILE *rf=fopen(REBUILD_FILE,"r");
          if(rf){ fclose(rf); remove(REBUILD_FILE);
              lg("*** alt: rebuild requested by hand (%s) ***",REBUILD_FILE);
              alt_force_rebuild=1; } }
        if(!alt_ctx_on || alt_stalled) continue;
        /* v65: Apple Maps only sends a frame when its picture CHANGES. With a
         * route active it puts a static turn card on the cluster ("Start on
         * Nashua St", decoded from the dump) and then sends nothing for as
         * long as the card stays the same. The old rule - no decoded frame
         * for STALL_SEC means the stream died - turned every static card into
         * a "crash" and handed the cluster back to the Porsche map. Same bug
         * as kamgurgul/mib2q-carplay#39, same cure: judge liveness by the
         * connection, not by frame timing. The receiver thread still releases
         * the cluster the moment the 111 connection actually ends.
         *
         * What stays: frames ARRIVING but none decoding is a real stall.
         * `echo 0 > /tmp/alt_quietok` restores the old frame-timing rule. */
        { time_t last=alt_last_ok, rx=alt_last_rx, now=time(0);
          int quiet_ok=1;
          { FILE*f=cfg_open("alt_quietok"); if(f){ int c=fgetc(f); fclose(f); quiet_ok=(c!='0'); } }
          if(last && now-last >= STALL_SEC){
              int arriving = rx && now-rx < STALL_SEC;
              if(quiet_ok && !arriving){
                  static time_t said;
                  if(now-said >= 30){ said=now;
                      lg("alt-watchdog: stream quiet for %ds — static picture, connection "
                         "open, keeping the cluster",(int)(now-last)); }
                  continue;
              }
              lg("*** alt-watchdog: frames %s but none decoded for %ds — asking for a "
                 "keyframe and handing the cluster back to the stock map ***",
                 arriving?"ARRIVING":"absent",(int)(now-last));
              if(alt_idr_permit(ALT_IDR_RECOVERY,"stall recovery"))
                  alt_send_cluster_idr("stall recovery");
              alt_stalled=1;
              alt_ctx_release_why("stalled");
          } }
    }
    lg("alt-watchdog: down");
    return 0;
}

static void *alt_geom_thread(void *a){
    (void)a;
    while(!alt_stop){
        alt_skip_load();
        alt_ptsmode_load();
        if(alt_nv_obj && alt_geom_load()) alt_geom_apply("file");
        sleep(1);
    }
    return 0;
}

/* Configure our cluster stream: copy the four undecoded configure() args from
 * the stock instance, then push an explicit 800x480 geometry block. */
static void alt_nv_configure(void){
    void *o=alt_nv_obj;
    if(!o){ lg("alt-nv cfg: no object"); return; }
    if(!nv_configure){ lg("alt-nv cfg: configure symbol missing"); return; }
    /* a3,a4 = source size; a5,a6 = destination offset. Decoded in v20 from the
     * stock call (1326,480,114,55), which matched SetAttribs words [5][6][7][8]. */
    unsigned a3=(unsigned)CLUSTER_W, a4=(unsigned)CLUSTER_H, a5=0, a6=0;  /* src = what the phone draws */
    lg("alt-nv cfg: explicit a3=%u a4=%u a5=%u a6=%u",a3,a4,a5,a6);
    int rc=nv_configure(o,(unsigned)PANEL_W,(unsigned)PANEL_H,a3,a4,a5,a6,(unsigned)alt_fps);
    lg("*** alt-nv cfg: configure(panel %d,%d, src %u,%u, off %u,%u, %d fps) -> %d ***",
       PANEL_W,PANEL_H,a3,a4,a5,a6,alt_fps,rc);

    alt_geom_load();
    alt_geom_apply("initial");

    /* v44: visibility belongs to the OBJECT, not to the process. Until now it
     * was set after the early return below, so it ran only for the first
     * object ever created; every rebuilt stream stayed invisible and the
     * cluster went black while frames decoded fine (rc=0). Only reachable
     * since v43 stopped the process from crashing at teardown. */
    if(nv_vis){ int vr=nv_vis(o,1); lg("alt-nv cfg: setVisibility(1) -> %d",vr); }

    if(alt_helpers_up) return;         /* reopening: threads already running */
    alt_helpers_up=1;
    {   pthread_t gt; pthread_attr_t ga;
        pthread_attr_init(&ga); pthread_attr_setdetachstate(&ga,PTHREAD_CREATE_DETACHED);
        if(pthread_create(&gt,&ga,alt_geom_thread,0)==0)
            lg("alt-geom: live tuner up — echo \"dispW dispH srcW srcH dstX dstY dstW dstH\" > /tmp/alt_geom");
        else lg("alt-geom: tuner thread failed");
        pthread_attr_destroy(&ga); }
    {   pthread_t wt; pthread_attr_t wa;
        pthread_attr_init(&wa); pthread_attr_setdetachstate(&wa,PTHREAD_CREATE_DETACHED);
        if(pthread_create(&wt,&wa,alt_watchdog_thread,0)!=0)
            lg("alt-watchdog: thread failed");
        pthread_attr_destroy(&wa); }
}

static void alt_nv_close(void){
    void *o=alt_nv_obj;
    if(!o) return;
    alt_nv_obj=0;
    lg("alt-nv: closing obj=%p",o);
    if(nv_stop) nv_stop(o);
    if(nv_dtor) nv_dtor(o);
    free(o);
    alt_nv_handle=0;                  /* v42: backstop, see NvSSVideoClose */
    lg("alt-nv: closed");
}


/* ===== the ONLY NvSS interpose v19 keeps: retarget our own open ========== */
typedef int (*fn_nvss_open_t)(void**, const void*);

__attribute__((visibility("default")))
int NvSSVideoOpen(void **outHandle, const void *attrs){
    static fn_nvss_open_t real=0;
    if(!real) real=(fn_nvss_open_t)dlsym(RTLD_NEXT,"NvSSVideoOpen");
    if(!real){ lg("NvSSVideoOpen real NULL"); return -1; }
    unsigned char mine[24];
    pthread_t claim=alt_nv_claim_thr;
    int is_ours = claim && pthread_equal(pthread_self(),claim);
    if(is_ours && attrs){
        memcpy(mine,attrs,24);
        mine[0]=(unsigned char)ALT_OUTPUT_DEV; mine[1]=0; mine[2]=0; mine[3]=0;
        mine[10]=(unsigned char)ALT_LAYER;
        lg("*** alt-nv: retargeting this open -> outputDevice=%d layer=%d ***",
           ALT_OUTPUT_DEV,ALT_LAYER);
        attrs=mine;
    }
    int rc=real(outHandle,attrs);
    if(!is_ours && rc==0 && outHandle){
        /* stock call: r0 was &stockThis->handle, so the object is outHandle-4 */
        alt_stock_obj=(void*)((char*)outHandle-4);
        lg("alt-nv: stock NvssVideoImpl object = %p",alt_stock_obj);
        /* The stock stream owns the shared state again. Do NOT rebuild our
         * stream here: that would run inside the stock open path on a dio
         * thread. Ask our own receiver thread to do it. */
        alt_stock_live=1;
        if(alt_feed_gate){ alt_reopen_req=1; lg("alt: reopen requested"); }
        else lg("alt: stock stream is back — our decoder never left, re-claiming "
                "the cluster on the next frame");
    }
    if(is_ours)
        lg("alt-nv: NvSSVideoOpen -> rc=%d handle=%p",rc,(outHandle?*outHandle:0));
    return rc;
}

/* ===== v29 instrumentation: when does the stock side tear down? ==========
 * Pure logging, no behaviour change. The question these answer is whether the
 * crash and the freeze follow the stock stream being stopped and its NvSS
 * session closed under us. ScreenStreamStop is exported from libairplay and
 * dio_manager calls it through its own PLT, exactly like Create and Start,
 * which we already interpose successfully. */
/* The precise moment the shared NvSS/libKD state loses its owner. A plain C
 * function with a known one-pointer signature, so no __builtin_apply
 * trampoline is involved - which is why v30's ScreenStreamStop interpose had
 * to go: doing real work between __builtin_apply_args() and __builtin_apply()
 * clobbers the saved argument block and the stock call gets garbage. */
/* ---- v34: do not let the stock stream be torn down at all -----------------
 *
 * Established by two core dumps (v32 and v33, identical top frames, tid 42/47):
 * the faulting thread is an NvSS-internal worker and OUR code is nowhere on its
 * stack. The worker faults during teardown whether our stream is open, idle, or
 * already closed. So the timing of our calls is irrelevant - what breaks is the
 * teardown itself, once a second NvSS stream has ever existed.
 *
 * The only cheap option left: while our cluster stream is live, swallow
 * ScreenStreamStop. The main screen's stream keeps running into a surface the
 * HMI no longer composites, and the teardown that kills us never happens.
 *
 * The deferred part matters: at unplug the session really must stop, or the
 * stream leaks and the next session may not come up. So we remember the stream
 * we swallowed and run the real stop when our receiver ends.
 *
 * EXPERIMENT, not a fix. Unknowns: how the AirPlay/HMI state machine reacts to
 * a stop that silently did nothing, and the extra decode load on a unit that
 * already logs "Late frame (348 ms)".
 */
typedef void *(*fn_sstop_t)(void*);
static fn_sstop_t   real_sstop;
static void *alt_pending_stop;      /* stream whose stop we swallowed */

static void alt_run_pending_stop(const char *why){
    void *st=alt_pending_stop;
    if(!st || !real_sstop) return;
    alt_pending_stop=0;
    lg("alt: running the deferred ScreenStreamStop(%p) now (%s)",st,why);
    real_sstop(st);
    lg("alt: deferred ScreenStreamStop returned");
}

__attribute__((visibility("default"))) void *ScreenStreamStop(void *stream){
    if(!real_sstop) real_sstop=(fn_sstop_t)dlsym(RTLD_NEXT,"ScreenStreamStop");
    lg("ScreenStreamStop(%p)  (ours: obj=%p handle=%p ctx_on=%d)",
       stream,alt_nv_obj,alt_nv_handle,alt_ctx_on);
    /* v34 swallowed this and it changed nothing: the libKD context is destroyed
     * by NvSSVideoClose, one level down. Pass-through again, logging only. */
    if(!real_sstop){ lg("ScreenStreamStop real NULL"); return 0; }
    void *r=real_sstop(stream);
    lg("ScreenStreamStop returned");
    return r;
}

/* ---- v39: stand down when the STOCK stream is stopped --------------------
 * With the decode starvation fixed (v37/v38: "Late frame" gone from sloginfo),
 * one problem is left, and the system log names the exact call it precedes:
 *
 *   ProcessFrames Error: -6753 kConnectionErr     <- leaving CarPlay
 *   StopSession / UpdateState READY -> STOPPING
 *   [NvssVideoImpl] [stop] <SCREEN> Stopped.      <- THIS
 *   run fault ... ip 0x783af1f4
 *
 * dio::NvssVideoImpl::stop is exported and takes only `this` (prologue:
 * "ldr r3,[r0,#4]" / "mov r5,r0"), so it can be interposed with a real
 * prototype - no __builtin_apply trampoline, which is what wrecked v30.
 * Earlier attempts hooked ScreenStreamStop, a level up, which also fires
 * during normal session setup and so could not be used for this. */
typedef void *(*fn_nvstop_t)(void*);

/* v41: close OUR stream, then swallow the stock's close.
 *
 * The evidence from v39 and v40 together is conclusive:
 *   - v39 closed ours first  -> the stock NvSSVideoClose entered and faulted;
 *   - v40 left ours open     -> the stock teardown completed for the first
 *     time, and OUR worker faulted ~8 s later.
 *
 * So libKD destroys its singleton context on the FIRST close and the second
 * close still needs it - which is why neither half worked alone. Doing both
 * at once covers both: our worker is gone because we closed, and the stock's
 * close never touches the destroyed context because we swallow it.
 *
 * The swallowed handles are simply leaked. dio_manager restarts per CarPlay
 * session, so the leak cannot outlive the session.
 *
 * The cluster release is handed to the watchdog: system() from inside the
 * stock stop path fails (observed rc=-1 in v40). */
static void alt_stand_down_full(void){
    if(alt_keep_alive()){
        /* Keep decoding; just give the cluster back. No gate, no close. */
        alt_stock_live=0;
        alt_release_req=1;
        lg("*** alt: stock stream stopped — KEEPING our decoder alive, cluster "
           "goes back to the Porsche map (obj=%p handle=%p) ***",
           alt_nv_obj,alt_nv_handle);
        return;
    }
    if(alt_feed_gate) return;
    alt_feed_gate=1;
    alt_au_collect=0;
    { int spins=0;
      while(alt_in_decode && spins++ < 2000) usleep(1000);
      if(alt_in_decode){ lg("alt: receiver STILL in decode — not closing"); return; } }
    alt_release_req=1;                    /* watchdog gives the cluster back */
    alt_nv_close();                       /* our worker must be gone */
    lg("alt: our stream closed; stock closes will now be swallowed");
}

__attribute__((visibility("default")))
void *_ZN3dio13NvssVideoImpl4stopEv(void *self){
    static fn_nvstop_t real=0;
    if(!real) real=(fn_nvstop_t)dlsym(RTLD_NEXT,"_ZN3dio13NvssVideoImpl4stopEv");
    int ours = (self && self==alt_nv_obj);
    lg("NvssVideoImpl::stop(%p) — %s (our obj=%p ctx_on=%d gate=%d)",
       self,ours?"OURS":"STOCK",alt_nv_obj,alt_ctx_on,alt_feed_gate);
    /* Our own alt_nv_close() calls this too, via nv_stop resolved with
     * RTLD_DEFAULT, so it lands here first; `ours` makes that a pass-through
     * and keeps the recursion one level deep. */
    if(!ours && alt_nv_obj && inject_level()>=7) alt_stand_down_full();
    if(!real){ lg("NvssVideoImpl::stop real NULL"); return 0; }
    void *r=real(self);
    lg("NvssVideoImpl::stop returned");
    return r;
}

typedef int (*fn_nvss_close_t)(void*);

/* Fast and allocation-free: this runs inside the stock teardown path, so it
 * must not call system() or block. Releasing the cluster context is left to
 * the watchdog, which notices the stall a moment later. */
/* Close our stream completely, in the one window where that is safe.
 *
 * The core dump settled this. The faulting thread (tid 42) had NO frame from
 * carplay_probe.so on its stack at all:
 *
 *   libnvss_video+0xcf88 -> +0xb510 -> +0xe110 -> libKD+0xa9e4
 *     -> libairplay+0x91294 -> libKD+0x9a60 -> +0xf920 -> +0xf8a4 -> CRASH
 *
 * It is an NvSS-internal worker thread. So the problem was never the timing of
 * OUR calls - it is that a SECOND NvSS stream exists while the first is being
 * torn down. One worker thread, one process-global libKD state: destroying one
 * stream nulls state the worker still uses for the other.
 *
 * Hence this must run BEFORE the stock teardown starts, i.e. from
 * ScreenStreamStop, while the stock stream is still alive and owns the shared
 * state. v31 did it from inside the stock NvSSVideoClose, which was already
 * too late and killed the stock close itself. */


/* ======================= v42: the actual root cause ======================
 * Static analysis of the car's own libKD.so (MU1416, 155648 B) finally named
 * the bug. The faulting instruction is libKD+0xf1f4:
 *
 *      f1dc: ldr r9,[pc,#416]        ; GOT base
 *      f1e0: ldr r3,[pc,#416]        ; GOT slot 0x3b4
 *      f1e8: ldr r3,[r9,r3]          ; &kd_state
 *      f1ec: ldr r5,[r3]             ; kd_state      <-- NULL
 *      f1f4: ldr r7,[r5,#20]         ; CRASH, NULL+0x14
 *
 * The enclosing function is 0xf1c0, and it is called from the exported
 * kdThreadCreate (bl at 0xf3c8). The pointer it reads is freed and nulled by
 * the internal function 0x7208:
 *
 *      7314: bl 0x6e80               ; free(state->...)
 *      7318: bl 0x6e80               ; free(state)
 *      7330: str #0,[r3]             ; kd_state = NULL     (GOT slot 0x3b4)
 *
 * and 0x7208 is reached from exactly one exported entry point:
 *
 *      kdTerminateNV (0x7a9c) -> 0x79b8 -> bl 0x7208 -> 0x7330
 *      (0x7a84 nulls a second pointer, GOT slot 0x384, the same way)
 *
 * kdTerminateNV takes no reference count: the FIRST caller frees libKD's
 * process-global state while the second NvSS stream is still using it. Both
 * `libnvss_video.so` and `libairplay.so` import kdInitializeNV/kdTerminateNV
 * by name, so the calls go through the PLT and are interposable from here.
 *
 * That explains every crash in this session and why eight permutations of the
 * close ordering all faulted at the same ip: the problem was never WHEN we
 * close, it is that the first teardown destroys libKD for the whole process.
 *
 * So: count the initialisations, swallow a kdTerminateNV that would run while
 * our stream is alive, and perform the real one from the watchdog once our
 * stream is gone. Nothing is patched; this is the missing refcount.
 * ======================================================================== */

typedef int  (*fn_kdinit_t)(void);
typedef void (*fn_kdterm_t)(void);

static volatile int kd_init_n;      /* successful kdInitializeNV calls seen  */
static volatile int kd_term_held;   /* kdTerminateNV calls we swallowed      */

/* v43: the same refcount, but as a GENERIC gate that does not depend on our
 * cluster stream or on the hook level at all.
 *
 * Reason: the owner reports that CarPlay sometimes crashed when the parking
 * sensors came on - BEFORE any of this was installed. That is the same shape
 * of bug: PDC/rear-view brings up a second video consumer while the CarPlay
 * screen stream is live, and whichever one is torn down first calls the
 * unrefcounted kdTerminateNV and frees libKD under the other.
 *
 * Supplying the missing refcount fixes that too - but it has to be active
 * while the feature itself is OFF, and "level 0 = complete passthrough" is the
 * one kill switch that works without a laptop. So this gets its OWN knob
 * instead of riding on the level, and it defaults to OFF.
 *
 *   echo 1 > /tmp/kd_guard                     # on, until the PCM reboots
 *   echo 1 > /mnt/app/eso/lib/kd_guard         # on, across reboots
 *   echo 0 > /tmp/kd_guard                     # off again, immediately
 *
 * The rule is the one libKD is missing, nothing more: a kdTerminateNV is only
 * performed when it is the LAST one owed. It is never suppressed outright, so
 * the final teardown still happens. */
/* v45: keep our decoder alive across a stock teardown instead of rebuilding
 * it. Rebuilding is what produced the black cluster on re-entry: a fresh NvSS
 * decoder got mid-GOP P-frames, since iOS does not re-offer stream 111 and so
 * never re-sends avcC or an IDR. Every feed returned 0 and nothing was drawn.
 *
 * Only safe now that kdTerminateNV is refcounted - this is exactly what v40
 * tried and could not survive. Default ON; `echo 0 > /tmp/alt_keep` restores
 * the v44 rebuild behaviour without rebuilding the library. */
#define KEEP_FILE "alt_keep"
static int alt_keep_alive(void){
    FILE *f=cfg_open(KEEP_FILE);
    if(!f) return 1;                       /* absent = on */
    int c=fgetc(f); fclose(f);
    return (c!='0');
}
#define KD_GUARD_FILE "kd_guard"
static int kd_guard(void){
    FILE *f=cfg_open(KD_GUARD_FILE);
    if(!f) return 0;                       /* absent = off */
    int c=fgetc(f); fclose(f);
    return (c=='1');
}

__attribute__((visibility("default")))
int kdInitializeNV(void){
    static fn_kdinit_t real=0;
    if(!real) real=(fn_kdinit_t)dlsym(RTLD_NEXT,"kdInitializeNV");
    if(!real){ lg("kdInitializeNV real NULL"); return -1; }
    int rc=real();
    if(rc==0) kd_init_n++;
    lg("kdInitializeNV -> %d (init_n=%d)",rc,kd_init_n);
    return rc;
}

__attribute__((visibility("default")))
void kdTerminateNV(void){
    static fn_kdterm_t real=0;
    if(!real) real=(fn_kdterm_t)dlsym(RTLD_NEXT,"kdTerminateNV");
    if(!real){ lg("kdTerminateNV real NULL"); return; }
    /* (a) our own cluster stream is alive: hold, the watchdog settles it. */
    if(inject_level()>=7 && (alt_nv_obj || alt_nv_handle)){
        kd_term_held++;
        lg("*** kdTerminateNV HELD (held=%d, init_n=%d, our obj=%p handle=%p) — "
           "running it now would free libKD's global state under our stream "
           "and fault at +0xf1f4 ***",kd_term_held,kd_init_n,alt_nv_obj,alt_nv_handle);
        return;
    }
    /* (b) v43 generic gate: more than one libKD user is still around, so this
     * terminate is not the last one owed. Decrement and return. */
    if(kd_guard()){
        if(kd_init_n>1){
            kd_init_n--;
            lg("*** kdTerminateNV REFCOUNTED (init_n now %d) — another libKD "
               "user is still live; not freeing the global state ***",kd_init_n);
            return;
        }
        if(kd_init_n<=0)
            lg("kd_guard: terminate with init_n=%d — unbalanced, passing it "
               "through",kd_init_n);
    }
    if(kd_guard() && kd_init_n>0) kd_init_n--;
    lg("kdTerminateNV -> real (held=%d, init_n=%d, guard=%d)",
       kd_term_held,kd_init_n,kd_guard());
    real();
}

/* Called from the watchdog thread once our own stream is gone: pay back the
 * terminate we owe libKD, exactly once per held call. */
static void kd_term_settle(void){
    static fn_kdterm_t real=0;
    if(alt_nv_obj || alt_nv_handle) return;
    if(kd_term_held<=0) return;
    if(!real) real=(fn_kdterm_t)dlsym(RTLD_NEXT,"kdTerminateNV");
    if(!real){ lg("kd_term_settle: real NULL"); kd_term_held=0; return; }
    while(kd_term_held>0){
        kd_term_held--;
        lg("kd_term_settle: our stream is gone — performing the deferred "
           "kdTerminateNV (%d left)",kd_term_held);
        real();
    }
}

__attribute__((visibility("default"))) int NvSSVideoClose(void *handle){
    static fn_nvss_close_t real=0;
    if(!real) real=(fn_nvss_close_t)dlsym(RTLD_NEXT,"NvSSVideoClose");
    int ours = (handle && handle==alt_nv_handle);
    lg("*** NvSSVideoClose(handle=%p) — %s (our handle=%p, ctx_on=%d, gate=%d) ***",
       handle, ours?"OURS":"STOCK", alt_nv_handle, alt_ctx_on, alt_feed_gate);
    if(!real){ lg("NvSSVideoClose real NULL"); return -1; }
    /* v42: the stock close is NEVER swallowed again. v41 proved the fault is
     * not in NvSSVideoClose at all - see the kdTerminateNV block below. */
    int rc=real(handle);
    /* v42: forget our handle, or kd_term_settle() would never see the stream
     * as gone and the held kdTerminateNV would never be paid back. */
    if(ours) alt_nv_handle=0;
    lg("NvSSVideoClose -> %d (our handle now %p)",rc,alt_nv_handle);
    return rc;
}



/* ===================== v51: showUI =========================================
 * From the altScreen protocol notes in ref/: the phone announces what it CAN
 * show with suggestUI{urls} - and the stock firmware answering -6714 there is
 * NORMAL, not the bug. The head unit is then expected to pick a scene and tell
 * the phone with a session command of its own:
 *
 *     showUI { uuid: <cluster display uuid>, url: <maps url> }
 *
 * We never sent it. Without a route Maps draws the cluster anyway, so this went
 * unnoticed; the moment guidance starts the phone waits to be told what the
 * cluster should show, is not told, and stops rendering it. That matches the
 * car exactly: cluster dies on route start, comes back when guidance is
 * switched off.
 *
 * Which URL: we have no route guidance of our own (this firmware has no iAP2
 * RGI at all), so we ask for map + cards - the phone then draws its own turn
 * card and ETA on the cluster, which is what we want anyway.
 *
 * Sent when our stream first decodes, and again whenever the phone asks with
 * suggestUI. `echo 0 > /tmp/alt_showui` disables it.
 * ========================================================================= */
#define ALT_CLUSTER_URL "maps:/car/instrumentcluster?showETA=yes&maneuverLayout=rightAligned&showSpeedLimit=no"

typedef int (*fn_sendcmd_t)(void*,void*,void*,void*);
void *alt_session;                 /* newest AirPlay session, from Setup */
static volatile int alt_showui_sent;

static int alt_showui_on(void){
    FILE *f=cfg_open("alt_showui");
    if(!f) return 0;                       /* absent = off (v73), see alt_suggestui_on */
    int c=fgetc(f); fclose(f);
    return (c!='0');
}

/* v54: after a scene change the phone does NOT start a new GOP on its own.
 * The accessory has to ask, with forceKeyFrame targeted at the cluster uuid -
 * stock's own AirPlayReceiverSessionForceKeyFrame sends no uuid and so hits
 * the main screen instead. This is also the missing half of our black-cluster
 * recovery: a rebuilt decoder has no IDR to start from until we ask for one.
 *
 * Deliberately no completion callback, and never sent from inside one: the
 * reference notes that chaining keyframe requests on completions grows the
 * firmware's async response queue. The watchdog thread ships it. */
volatile int alt_idr_req;

/* v64: keyframe request policy, modelled on ref recovery_policy.h.
 *
 * Car evidence (one session, two route starts, same build): the route that
 * WORKED produced one forceKeyFrame; the one that FAILED produced three in four
 * seconds (two showUI answers + the stall watchdog), the phone re-sent avcC
 * after each, and the stream stalled. The reference says why: "each keyframe
 * request triggers ~1s of heavy refining P-frames from the phone", and it
 * rate-limits accordingly:
 *   - scene-change requests: at most one per ALT_IDR_UI_GAP;
 *   - stall recovery: 2 s, then 4 s, then 8 s between requests, reset as soon
 *     as frames decode again;
 *   - a decoder rebuild always gets one. */
#define ALT_IDR_UI_GAP_US   2000000ULL
static unsigned long long alt_idr_last_us, alt_idr_due_us;
static int alt_idr_backoff;

static unsigned long long alt_now_us(void){
    struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC,&ts)!=0) return 0;
    return (unsigned long long)ts.tv_sec*1000000ULL+(unsigned long long)(ts.tv_nsec/1000);
}

/* called when frames decode again: recovery is over */
static void alt_idr_healthy(void){ alt_idr_backoff=0; alt_idr_due_us=0; }

static int alt_idr_permit(int kind,const char *why){
    unsigned long long now=alt_now_us();
    if(kind==ALT_IDR_REBUILD){ alt_idr_last_us=now; return 1; }
    if(kind==ALT_IDR_UI){
        if(alt_idr_last_us && now-alt_idr_last_us < ALT_IDR_UI_GAP_US){
            lg("forceKeyFrame coalesced (%s): last one %llu ms ago",
               why,(now-alt_idr_last_us)/1000ULL);
            return 0;
        }
        alt_idr_last_us=now; return 1;
    }
    /* recovery: exponential backoff 2 / 4 / 8 s */
    if(alt_idr_due_us && now < alt_idr_due_us){
        lg("forceKeyFrame held back (%s): recovery backoff, %llu ms to go",
           why,(alt_idr_due_us-now)/1000ULL);
        return 0;
    }
    { int shift=alt_idr_backoff<2?alt_idr_backoff:2;
      alt_idr_due_us=now+(2000000ULL<<shift); }
    if(alt_idr_backoff<32) alt_idr_backoff++;
    alt_idr_last_us=now;
    return 1;
}

static int alt_send_cluster_idr(const char *why){
    static fn_sendcmd_t send=0;
    if(!alt_session){ lg("forceKeyFrame: no session (%s)",why); return -1; }
    if(cf_init()!=1) return -1;
    if(!send) send=(fn_sendcmd_t)dlsym(RTLD_DEFAULT,"AirPlayReceiverSessionSendCommand");
    if(!send){ lg("forceKeyFrame: SendCommand missing"); return -1; }
    void *params=cf_dictm(0,0,dict_keycb,dict_valcb);
    void *cmd=cf_dictm(0,0,dict_keycb,dict_valcb);
    void *pk=cf_str(0,"params",CFENC_UTF8);
    int rc=-1;
    if(params && cmd && pk &&
       set_str(params,"uuid",CLUSTER_UUID)==0 &&
       set_str(cmd,"type","forceKeyFrame")==0){
        cf_dictset(cmd,pk,params);
        rc=send(alt_session,cmd,0,0);
        lg("*** forceKeyFrame asked for the cluster (%s) -> %d ***",why,rc);
    }
    if(pk)cf_rel(pk); if(cmd)cf_rel(cmd); if(params)cf_rel(params);
    return rc;
}

/* v58: the reference ships THREE commands once the cluster stream is live -
 * showUI, setNightMode and updateViewArea. We only ever sent the first. The
 * dump from a failing route shows the phone encoding an EMPTY 1200x720 window
 * (IDR 2.4 KB against 38 KB in a working session), so the scene is selected
 * but the window is not in a state the app draws into. updateViewArea is the
 * command that tells CarKit which view area is current - without it
 * CARScreenInfo.currentViewArea keeps whatever it had, which is observably
 * different from the native helper. */
static int alt_send_viewarea(const char *why){
    static fn_sendcmd_t send=0;
    if(!alt_session) return -1;
    if(cf_init()!=1) return -1;
    if(!send) send=(fn_sendcmd_t)dlsym(RTLD_DEFAULT,"AirPlayReceiverSessionSendCommand");
    if(!send) return -1;
    void *params=cf_dictm(0,0,dict_keycb,dict_valcb);
    void *cmd=cf_dictm(0,0,dict_keycb,dict_valcb);
    void *pk=cf_str(0,"params",CFENC_UTF8);
    void *ak=cf_str(0,"adjacentViewAreas",CFENC_UTF8);
    void *adj=cf_arrm(0,0,arr_cb);          /* [] - view area 0 is current */
    int rc=-1;
    if(params && cmd && pk && ak && adj &&
       set_str(params,"uuid",CLUSTER_UUID)==0 &&
       set_i64(params,"viewAreaIndex",0)==0 &&
       set_i64(params,"animationDurationMillis",250)==0 &&
       set_str(cmd,"type","updateViewArea")==0){
        cf_dictset(params,ak,adj);
        cf_dictset(cmd,pk,params);
        rc=send(alt_session,cmd,0,0);
        lg("*** updateViewArea sent (%s): index=0 adjacent=[] -> %d ***",why,rc);
    }
    if(adj)cf_rel(adj); if(ak)cf_rel(ak); if(pk)cf_rel(pk);
    if(cmd)cf_rel(cmd); if(params)cf_rel(params);
    return rc;
}

static int alt_send_nightmode(int night,const char *why){
    static fn_sendcmd_t send=0;
    if(!alt_session) return -1;
    if(cf_init()!=1) return -1;
    if(!send) send=(fn_sendcmd_t)dlsym(RTLD_DEFAULT,"AirPlayReceiverSessionSendCommand");
    if(!send) return -1;
    void *params=cf_dictm(0,0,dict_keycb,dict_valcb);
    void *cmd=cf_dictm(0,0,dict_keycb,dict_valcb);
    void *pk=cf_str(0,"params",CFENC_UTF8);
    int rc=-1;
    if(params && cmd && pk &&
       set_str(params,"uuid",CLUSTER_UUID)==0 &&
       set_i64(params,"nightMode",night?1:0)==0 &&
       set_str(cmd,"type","setNightMode")==0){
        cf_dictset(cmd,pk,params);
        rc=send(alt_session,cmd,0,0);
        lg("*** setNightMode(%d) sent (%s) -> %d ***",night,why,rc);
    }
    if(pk)cf_rel(pk); if(cmd)cf_rel(cmd); if(params)cf_rel(params);
    return rc;
}

/* v74: cluster map zoom through Apple Maps' own semantic command.
 *   {type: "changeMapZoomLevel", params: {uuid: <cluster uuid>, zoomDirection}}
 *   zoomDirection 0 = zoom in, nonzero = zoom out (ref command_worker.h, keys
 *   verified there on MHI3 450; DashBoard matches uuid against the cluster
 *   display and emits CRSUIClusterZoomAction - iOS animates the map itself).
 * Runtime:  echo 3 > /tmp/alt_zoom    three steps out
 *           echo -2 > /tmp/alt_zoom   two steps in
 * Default applied a few seconds after every stream start (persistent tier
 * works too):  echo 2 > /mnt/app/eso/lib/alt_zoom_default
 * One step per watchdog tick, so the phone is never flooded. */
static void alt_zoom_done(int status,void *resp,void *ctx){
    (void)resp;
    lg("changeMapZoomLevel ack: status=%d (%s)",status,(const char*)(ctx?ctx:"?"));
}

static int alt_send_zoom(int out){
    static fn_sendcmd_t send=0;
    if(!alt_session) return -1;
    if(cf_init()!=1) return -1;
    if(!send) send=(fn_sendcmd_t)dlsym(RTLD_DEFAULT,"AirPlayReceiverSessionSendCommand");
    if(!send) return -1;
    void *params=cf_dictm(0,0,dict_keycb,dict_valcb);
    void *cmd=cf_dictm(0,0,dict_keycb,dict_valcb);
    void *pk=cf_str(0,"params",CFENC_UTF8);
    int rc=-1;
    if(params && cmd && pk &&
       set_str(params,"uuid",CLUSTER_UUID)==0 &&
       set_i64(params,"zoomDirection",out?1:0)==0 &&
       set_str(cmd,"type","changeMapZoomLevel")==0){
        cf_dictset(cmd,pk,params);
        rc=send(alt_session,cmd,(void*)alt_zoom_done,(void*)(out?"out":"in"));
        lg("*** changeMapZoomLevel %s sent -> %d ***",out?"OUT":"IN",rc);
    }
    if(pk)cf_rel(pk); if(cmd)cf_rel(cmd); if(params)cf_rel(params);
    return rc;
}

static int  alt_zoom_pending;
static time_t alt_zoom_live_since;
static int  alt_zoom_default_done;

static int alt_read_int_file(FILE *f,int *v){
    char b[32]; int n; if(!f) return 0;
    n=(int)fread(b,1,sizeof b-1,f); fclose(f); b[n>0?n:0]=0;
    return sscanf(b,"%d",v)==1;
}

/* watchdog tick */
static void alt_zoom_tick(void){
    int v;
    FILE *f=fopen("/tmp/alt_zoom","r");
    if(f){ if(alt_read_int_file(f,&v) && v>=-20 && v<=20){ alt_zoom_pending+=v;
               lg("alt-zoom: %+d steps requested (pending %+d)",v,alt_zoom_pending); }
           remove("/tmp/alt_zoom"); }
    if(!alt_ctx_on){ alt_zoom_live_since=0; alt_zoom_default_done=0; return; }
    if(!alt_zoom_live_since) alt_zoom_live_since=time(0);
    if(!alt_zoom_default_done && time(0)-alt_zoom_live_since>=4){
        alt_zoom_default_done=1;
        if(alt_read_int_file(cfg_open("alt_zoom_default"),&v) && v>=-20 && v<=20 && v){
            alt_zoom_pending+=v;
            lg("alt-zoom: applying default %+d steps for this stream",v);
        }
    }
    if(alt_zoom_pending){
        int out = alt_zoom_pending>0;
        if(alt_send_zoom(out)==0) alt_zoom_pending += out?-1:1;
        else { lg("alt-zoom: send failed, dropping %+d pending",alt_zoom_pending); alt_zoom_pending=0; }
    }
}

static void alt_showui_done(int status,void *resp,void *ctx){
    lg("*** showUI ANSWER from the phone: status=%d resp=%p (%s) ***",
       status,resp,(const char*)(ctx?ctx:"?"));
    if(status==0 && !alt_showui_acked){       /* once per stream, not per answer */
        alt_showui_acked=1; alt_idr_req=ALT_IDR_UI; alt_va_req=1;
    }
}

/* v53: the phone offers ONE url at a time and it CHANGES with the navigation
 * state - measured on the car: 'maps:/car/instrumentcluster/map' first, then
 * 'maps:/car/instrumentcluster'. Our v51/v52 always answered with the same
 * decorated url (?showETA=yes&maneuverLayout=rightAligned...). CarKit accepted
 * the command (status=0) but intersects the url with what the app actually
 * offers, so a decorated url that is not in that list selects nothing.
 *
 * So echo back exactly what was suggested, and re-send whenever it changes -
 * a repeat of an identical showUI is known not to be observable to the phone. */
static char alt_sugg_url[256];

/* v56: which scene we ask for, switchable at runtime without a rebuild.
 *   echo map  > /tmp/alt_scene   -> maps:/car/instrumentcluster/map   (itemType 1, map only)
 *   echo root > /tmp/alt_scene   -> maps:/car/instrumentcluster       (itemType 3, map + cards)
 *   echo deco > /tmp/alt_scene   -> root + ?showETA=yes&maneuverLayout=rightAligned&showSpeedLimit=no
 *   echo echo > /tmp/alt_scene   -> mirror whatever the phone last suggested (v53 behaviour)
 *   echo none > /tmp/alt_scene   -> never send showUI at all (stock behaviour)
 * Default: deco (v67) - map + turn cards, the setting proven on the car.
 *
 * Why this matters: CarPlay.framework only creates the app's cluster window for
 * itemType 1 or 3 (`updateSceneForNewItemTypeSetting`). `.../instructioncard`
 * is itemType 2 - card only, no window, no video. Mirroring the phone's
 * suggestion can therefore hand us a scene that cannot produce a picture. */
static void alt_scene_mode(char *out,int n){
    char buf[32]; int k=0;
    FILE *f=cfg_open("alt_scene");
    if(f){ k=(int)fread(buf,1,sizeof(buf)-1,f); fclose(f); }
    buf[k>0?k:0]=0;
    while(k>0 && (buf[k-1]=='\n'||buf[k-1]=='\r'||buf[k-1]==' ')) buf[--k]=0;
    if(!k) snprintf(buf,sizeof buf,"map");    /* v68: owner wants the map on the cluster, arrows go to the HUD */
    snprintf(out,n,"%s",buf);
}

static const char *alt_scene_url(void){
    static char mode[32];
    /* v70: a literal URL in /tmp/alt_scene is used verbatim, so scene
     * experiments need no rebuild:
     *   echo 'maps:/car/instrumentcluster/map?mapsPresentation=map' > /tmp/alt_scene */
    { static char lit[256]; FILE *f=cfg_open("alt_scene");
      if(f){ int n=(int)fread(lit,1,sizeof lit-1,f); fclose(f); lit[n>0?n:0]=0;
             while(n>0 && (lit[n-1]=='\n'||lit[n-1]=='\r'||lit[n-1]==' ')) lit[--n]=0;
             if(!strncmp(lit,"maps:",5)) return lit; } }
    alt_scene_mode(mode,sizeof mode);
    if(!strcmp(mode,"root")) return "maps:/car/instrumentcluster";
    if(!strcmp(mode,"deco")) return ALT_CLUSTER_URL;
    if(!strcmp(mode,"echo")) return alt_sugg_url[0]?alt_sugg_url:"maps:/car/instrumentcluster";
    if(!strcmp(mode,"none")) return 0;
    /* v69: map only, no ETA, no maneuver card - the reference uses exactly
     * this when the car draws the arrows itself, which is now our case: the
     * arrows go to the HUD through the Porsche BAP bridge. */
    /* v70: Apple Maps' own cluster content follows mapsPresentation=, not the
     * /map path (ref THIRD_PARTY_NAV_APPS: "mapsPresentation=anycontent / map /
     * instructioncard -> itemType 3 / 1 / 2 (Maps-hosted content)"). v69 sent
     * /map without it: accepted with status 0, and Maps kept its full-screen
     * turn card - verified by decoding the cluster stream. */
    /* v72: exactly the reference's RGI-on URL (map only, the car draws the
     * arrows). v70 added mapsPresentation=map, which the working reference
     * does not use - back to the proven string. */
    return "maps:/car/instrumentcluster/map?showETA=no&maneuverLayout=no&showSpeedLimit=no";
}

static int alt_send_showui(const char *why){
    static fn_sendcmd_t send=0;
    if(!alt_showui_on()) return -1;
    const char *url=alt_scene_url();
    if(!url){ lg("showUI: scene mode 'none' — not sending (%s)",why); return -1; }
    if(!alt_session){ lg("showUI: no session yet (%s)",why); return -1; }
    /* v64: an identical showUI is not observable to the phone, but every
     * answer to it used to trigger another updateViewArea + forceKeyFrame. */
    if(alt_showui_acked && !strcmp(url,alt_showui_last)){
        lg("showUI skipped (%s): '%s' already shown on this stream",why,url);
        alt_showui_sent=1;
        return 0;
    }
    if(cf_init()!=1){ lg("showUI: CF not ready"); return -1; }
    if(!send) send=(fn_sendcmd_t)dlsym(RTLD_DEFAULT,"AirPlayReceiverSessionSendCommand");
    if(!send){ lg("showUI: AirPlayReceiverSessionSendCommand missing"); return -1; }
    void *params=cf_dictm(0,0,dict_keycb,dict_valcb);
    void *cmd=cf_dictm(0,0,dict_keycb,dict_valcb);
    void *pk=cf_str(0,"params",CFENC_UTF8);
    int rc=-1;
    if(params && cmd && pk &&
       set_str(params,"uuid",CLUSTER_UUID)==0 &&
       set_str(params,"url",url)==0 &&
       set_str(cmd,"type","showUI")==0){
        cf_dictset(cmd,pk,params);
        rc=send(alt_session,cmd,(void*)alt_showui_done,(void*)why);
        lg("*** showUI sent (%s): uuid=%s url=%s -> %d ***",why,CLUSTER_UUID,url,rc);
        if(rc==0){ alt_showui_sent=1; snprintf(alt_showui_last,sizeof alt_showui_last,"%s",url); }
    } else lg("showUI: building the command failed");
    if(pk)cf_rel(pk); if(cmd)cf_rel(cmd); if(params)cf_rel(params);
    return rc;
}

/* ===================== v49: suggestUI =====================================
 * Observed on the car the moment a route is started in Apple Maps:
 *
 *   [AirPlay] <ERROR> Command 'suggestUI' failed: 422/0x1A6 Unprocessable
 *             Entity, -6714/0xFFFFE5C6 kNotHandledErr
 *
 * and the cluster stream simply STOPS - no more frames arrive at all, our
 * watchdog sees no decode for 3 s and hands the cluster back to the Porsche
 * map. The decoder is not involved: the phone stopped sending.
 *
 * suggestUI is how iOS asks the head unit to bring a URL up on a display -
 * for us maps:/car/instrumentcluster, the very URL we advertise in
 * altScreenSuggestUIURLs. The firmware knows nothing about the display we
 * injected into /info, so its platform handler answers kNotHandledErr, and
 * iOS concludes the display is not there and stops rendering it.
 *
 * So answer for it. The cluster is already showing that URL's stream, so
 * reporting success is true in effect. Only the error case is touched: if the
 * firmware handles a command itself, its own result is returned untouched.
 *
 * `echo 0 > /tmp/alt_suggestui` disables the override and leaves pure logging.
 * ========================================================================= */
typedef int32_t (*fn_platctl_t)(void*,unsigned,const void*,const void*,const void*,void**);
typedef int   (*fn_cfgetcstr_t)(const void*,char*,long,unsigned);
typedef long  (*fn_cflen_t)(const void*);

/* v73: OFF by default. Proven on the car 2026-11-07: with initialURL = map
 * only, the cluster held the Apple Maps map with a route only once we stopped
 * answering the phone's suggestUI with OK and stopped our own showUI burst.
 * With either active the map showed for ~1 s and the full-screen turn card
 * took over. The stock answer (-6714 / 422) to suggestUI is what keeps the
 * scene chosen by initialURL.  echo 1 > /tmp/alt_suggestui re-enables. */
static int alt_suggestui_on(void){
    FILE *f=cfg_open("alt_suggestui");
    if(!f) return 0;                       /* absent = off (v73) */
    int c=fgetc(f); fclose(f);
    return (c!='0');
}

/* Best-effort CFString -> C string; returns "" when it is not a CFString. */
static const char *cfs(const void *s,char *buf,int n){
    static fn_cfgetcstr_t get=0; static int tried=0;
    buf[0]=0;
    if(!s) return buf;
    if(!tried){ tried=1; get=(fn_cfgetcstr_t)dlsym(RTLD_DEFAULT,"CFStringGetCString"); }
    if(!get) return buf;
    if(!get(s,buf,n,CFENC_UTF8)) buf[0]=0;
    buf[n-1]=0;
    return buf;
}

__attribute__((visibility("default")))
int32_t AirPlayReceiverSessionPlatformControl(void *session,unsigned flags,
        const void *cmd,const void *qual,const void *params,void **outParams){
    static fn_platctl_t real=0;
    if(!real) real=(fn_platctl_t)dlsym(RTLD_NEXT,"AirPlayReceiverSessionPlatformControl");
    char cb[64];
    const char *name=cfs(cmd,cb,sizeof cb);
    if(name[0] && !strcmp(name,"suggestUI")){
        char qb[160]; qb[0]=0;
        /* the qualifier is usually the URL itself; params may hold uuid/url */
        lg("suggestUI: qualifier='%s'",cfs(qual,qb,sizeof qb));
        /* v52: the phone sends suggestUI{urls:[...]} - these are the scenes it
         * is willing to show. CarKit intersects our showUI url with this list,
         * so if ours is not in it, showUI is silently useless. */
        if(params && cf_getval && cf_str && cf_arrcnt && cf_arrget){
            void *k=cf_str(0,"urls",CFENC_UTF8);
            void *a=k?cf_getval((void*)params,k):0;
            if(a){
                long n=cf_arrcnt(a), i;
                lg("suggestUI: the phone offers %ld url(s)",n);
                for(i=0;i<n && i<8;i++){
                    char vb[200];
                    const char *u=cfs(cf_arrget(a,i),vb,sizeof vb);
                    lg("suggestUI:   [%ld] '%s'",i,u);
                    if(i==0 && u[0] && strcmp(u,alt_sugg_url)){
                        snprintf(alt_sugg_url,sizeof alt_sugg_url,"%s",u);
                        alt_showui_sent=0;      /* the scene changed: answer again */
                        lg("suggestUI: scene changed -> '%s'",alt_sugg_url);
                    }
                }
            } else lg("suggestUI: no 'urls' array in params (params=%p)",params);
            if(k) cf_rel(k);
        }
    }
    if(!real){ lg("PlatformControl('%s') real NULL",name); return -6714; }
    int32_t rc=real(session,flags,cmd,qual,params,outParams);
    if(rc!=0 || name[0])
        lg("PlatformControl('%s') -> %d",name,(int)rc);
    if(rc==-6714 && name[0] && !strcmp(name,"suggestUI") && inject_level()>=7
       && alt_suggestui_on()){
        /* v55: do NOT ship a session command from inside the phone's own
         * command handler. The reference implementation ships every command
         * from a worker thread for exactly this reason; sending showUI here
         * means we are talking back while the firmware has not yet answered
         * the request we are standing in. Hand it to the watchdog. */
        /* v69: the phone re-suggests a scene when guidance starts (/map, then
         * the root = anyContent = full-screen turn card). v64 deduplicated our
         * answers per stream, so after the first one we went silent - and an
         * unanswered suggestion leaves the phone on its own pick: the grey
         * card. Every suggestion gets an answer; the watchdog ships at most one
         * per tick, so a burst of suggestions still yields a single showUI. */
        alt_showui_acked=0;
        lg("suggestUI: the phone is asking which scene to show — queued showUI for the worker");
        alt_showui_req=1;
        if(outParams) *outParams=0;
        return 0;
    }
    return rc;
}


/* ===================== v68: NvMedia surface probe =========================
 * Goal: read the MAIN CarPlay picture that the hardware has already decoded,
 * to find Apple Maps' maneuver banner for the HUD arrows - without a software
 * decoder. dmdt ts cannot do it: it captures only the HMI graphics layer, the
 * NvSS video layers come out empty (verified on the car).
 *
 * libnvss_video drives the whole video path through NvMedia, imported by name:
 *   0x4554 NvMediaVideoSurfaceCreate(device, type, (w+15)&~15, (h+15)&~15)
 *   0x53b0 NvMediaVideoDecoderRender(decoder, target, &picInfo, 1, &bitstreams)
 *   0x91f4 NvMediaVideoSurfaceLock(surface, &map)  map on its stack, <= 228 B
 *          NvMediaVideoSurfaceUnlock(surface)
 * So: remember which surface the MAIN decoder rendered into last (the main
 * screen is the one with width >= 1300), and on request lock it from our own
 * thread, log the raw map words (their values give the layout away: sizes,
 * plane pointers, pitches) and optionally dump part of a plane.
 *
 *   echo 1 > /tmp/nv_probe                 lock + log the map words
 *   echo "16 20 480 1328" > /tmp/nv_probe  also dump <rows> x <cols> bytes of
 *                                          the plane whose pointer is at byte
 *                                          offset 16 and pitch at offset 20
 *                                          -> /tmp/nv_plane.raw
 * Logging only; nothing changes for the stock pipeline.
 * ========================================================================= */
typedef void *(*fn_nvm_surf_create_t)(void*,int,unsigned,unsigned);
typedef int   (*fn_nvm_dec_render_t)(void*,void*,void*,unsigned,void*);
typedef int   (*fn_nvm_surf_lock_t)(void*,void*);
typedef void  (*fn_nvm_surf_unlock_t)(void*);

#define NVP_MAX 48
static struct { void *s; unsigned w,h; int type; } nvp_surf[NVP_MAX];
static int nvp_n;
static void *volatile nvp_last_main;
static unsigned nvp_main_w, nvp_main_h;
static pthread_mutex_t nvp_mx = PTHREAD_MUTEX_INITIALIZER;

static int nvp_find(void *s, unsigned *w, unsigned *h){
    int i;
    for(i=0;i<nvp_n;i++) if(nvp_surf[i].s==s){ if(w)*w=nvp_surf[i].w; if(h)*h=nvp_surf[i].h; return i; }
    return -1;
}

__attribute__((visibility("default")))
void *NvMediaVideoSurfaceCreate(void *device,int type,unsigned w,unsigned h){
    static fn_nvm_surf_create_t real=0;
    if(!real) real=(fn_nvm_surf_create_t)dlsym(RTLD_NEXT,"NvMediaVideoSurfaceCreate");
    void *r = real?real(device,type,w,h):0;
    pthread_mutex_lock(&nvp_mx);
    if(r && nvp_find(r,0,0)<0 && nvp_n<NVP_MAX){
        nvp_surf[nvp_n].s=r; nvp_surf[nvp_n].w=w; nvp_surf[nvp_n].h=h; nvp_surf[nvp_n].type=type; nvp_n++;
    }
    pthread_mutex_unlock(&nvp_mx);
    lg("nvprobe: SurfaceCreate(type=%d %ux%u) -> %p",type,w,h,r);
    return r;
}

__attribute__((visibility("default")))
int NvMediaVideoDecoderRender(void *dec,void *target,void *pic,unsigned n,void *bs){
    static fn_nvm_dec_render_t real=0;
    static unsigned long calls;
    if(!real) real=(fn_nvm_dec_render_t)dlsym(RTLD_NEXT,"NvMediaVideoDecoderRender");
    int rc = real?real(dec,target,pic,n,bs):-1;
    { unsigned w=0,h=0;
      pthread_mutex_lock(&nvp_mx);
      nvp_find(target,&w,&h);
      if(w>=1300){ nvp_last_main=target; nvp_main_w=w; nvp_main_h=h; }
      pthread_mutex_unlock(&nvp_mx);
      if(++calls<=3 || (calls%1800)==0)
          lg("nvprobe: DecoderRender(dec=%p target=%p %ux%u) -> %d (#%lu)",dec,target,w,h,rc,calls); }
    return rc;
}

__attribute__((visibility("default")))
int NvMediaVideoSurfaceLock(void *surface,void *map){
    static fn_nvm_surf_lock_t real=0;
    static int logged;
    if(!real) real=(fn_nvm_surf_lock_t)dlsym(RTLD_NEXT,"NvMediaVideoSurfaceLock");
    int rc = real?real(surface,map):-1;
    if(logged<4 && map){
        unsigned *w=(unsigned*)map; logged++;
        lg("nvprobe: stock Lock(%p) -> %d map: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x",
           surface,rc,w[0],w[1],w[2],w[3],w[4],w[5],w[6],w[7],w[8],w[9],w[10],w[11]);
    }
    return rc;
}

/* v69: banner sample collector for the HUD-arrow recogniser.
 *   echo 1 > /tmp/bnr_collect      start collecting (off by default)
 * Once a second, while enabled, lock the newest MAIN-screen surface and copy
 * the Apple Maps guidance banner area of the luma plane (map layout read on
 * the car: +8 pY, +12 pitchY). A crop is saved only when it differs visibly
 * from the last saved one, so a drive yields one sample per banner change.
 * Flat files (/tmp is a ramdisk without subdirectories), capped at BNR_MAX.
 * Nothing is shown anywhere - this only gathers the images to build the
 * recogniser from. */
#define BNR_X 80
#define BNR_Y 0
#define BNR_W 400
#define BNR_H 160
#define BNR_MAX 150
static void bnr_collect(void){
    static fn_nvm_surf_lock_t lock=0; static fn_nvm_surf_unlock_t unlock=0;
    static unsigned char last[(BNR_W/8)*(BNR_H/8)];
    static int have_last, saved;
    static unsigned char crop[BNR_W*BNR_H];
    FILE *f=fopen("/tmp/bnr_collect","r");
    if(!f) return;
    fclose(f);
    if(saved>=BNR_MAX) return;
    if(!lock) lock=(fn_nvm_surf_lock_t)dlsym(RTLD_NEXT,"NvMediaVideoSurfaceLock");
    if(!unlock) unlock=(fn_nvm_surf_unlock_t)dlsym(RTLD_NEXT,"NvMediaVideoSurfaceUnlock");
    void *s=nvp_last_main;
    if(!s || !lock || !unlock) return;
    unsigned char mapb[256]; memset(mapb,0,sizeof mapb);
    if(lock(s,mapb)!=0) return;
    unsigned char *py=*(unsigned char**)(mapb+8);
    unsigned pitch=*(unsigned*)(mapb+12);
    unsigned w=*(unsigned*)(mapb+0), h=*(unsigned*)(mapb+4);
    if(py && pitch>=BNR_X+BNR_W && w>=BNR_X+BNR_W && h>=BNR_Y+BNR_H){
        int r; for(r=0;r<BNR_H;r++) memcpy(crop+(size_t)r*BNR_W, py+(size_t)(BNR_Y+r)*pitch+BNR_X, BNR_W);
    } else { unlock(s); return; }
    unlock(s);
    /* coarse 8x8-block signature; save on a visible change */
    { unsigned char sig[(BNR_W/8)*(BNR_H/8)]; int bx,by; unsigned long diff=0;
      for(by=0;by<BNR_H/8;by++) for(bx=0;bx<BNR_W/8;bx++){
          unsigned sum=0; int yy,xx;
          for(yy=0;yy<8;yy+=2) for(xx=0;xx<8;xx+=2) sum+=crop[(by*8+yy)*BNR_W+bx*8+xx];
          sig[by*(BNR_W/8)+bx]=(unsigned char)(sum/16);
      }
      if(have_last){ int i; for(i=0;i<(int)sizeof sig;i++){ int d=(int)sig[i]-(int)last[i]; diff+= d<0?-d:d; } }
      if(have_last && diff < (unsigned long)(sizeof sig)*3) return;   /* mean change < 3 levels */
      memcpy(last,sig,sizeof sig); have_last=1; }
    { char path[64]; FILE *o;
      snprintf(path,sizeof path,"/tmp/bnr_%03d.raw",saved);
      o=fopen(path,"wb");
      if(o){ fwrite(crop,1,sizeof crop,o); fclose(o); saved++;
             lg("bnr: saved %s (%dx%d, sample %d/%d)",path,BNR_W,BNR_H,saved,BNR_MAX); } }
}

/* called from the watchdog thread */
static void nvp_probe(void){
    static fn_nvm_surf_lock_t lock=0; static fn_nvm_surf_unlock_t unlock=0;
    char buf[64]; int n=0; int offp=-1,offpitch=-1,rows=0,cols=0;
    FILE *f=fopen("/tmp/nv_probe","r");
    if(!f) return;
    n=(int)fread(buf,1,sizeof buf-1,f); fclose(f); remove("/tmp/nv_probe");
    buf[n>0?n:0]=0;
    sscanf(buf,"%d %d %d %d",&offp,&offpitch,&rows,&cols);
    if(!lock) lock=(fn_nvm_surf_lock_t)dlsym(RTLD_NEXT,"NvMediaVideoSurfaceLock");
    if(!unlock) unlock=(fn_nvm_surf_unlock_t)dlsym(RTLD_NEXT,"NvMediaVideoSurfaceUnlock");
    void *s=nvp_last_main;
    if(!s || !lock || !unlock){ lg("nvprobe: nothing to lock (surface=%p lock=%p)",s,lock); return; }
    unsigned char mapb[256]; memset(mapb,0,sizeof mapb);
    int rc=lock(s,mapb);
    unsigned *w=(unsigned*)mapb;
    lg("nvprobe: PROBE Lock(%p %ux%u) -> %d",s,nvp_main_w,nvp_main_h,rc);
    { int i; for(i=0;i<24;i+=6)
        lg("nvprobe:   map[+%02d] %08x %08x %08x %08x %08x %08x",i*4,w[i],w[i+1],w[i+2],w[i+3],w[i+4],w[i+5]); }
    if(rc==0 && offp>=0 && offpitch>=0 && rows>0 && cols>0 && offp<252 && offpitch<252){
        unsigned char *plane=*(unsigned char**)(mapb+offp);
        unsigned pitch=*(unsigned*)(mapb+offpitch);
        if(rows>720) rows=720;
        if(cols>(int)pitch) cols=(int)pitch;
        FILE *o=fopen("/tmp/nv_plane.raw","wb");
        if(o && plane){
            int r; for(r=0;r<rows;r++) fwrite(plane+(size_t)r*pitch,1,(size_t)cols,o);
            lg("nvprobe: dumped %d x %d bytes (pitch %u) from %p -> /tmp/nv_plane.raw",rows,cols,pitch,plane);
        } else lg("nvprobe: dump failed (plane=%p)",plane);
        if(o) fclose(o);
    }
    unlock(s);
    lg("nvprobe: unlocked");
}

__attribute__((destructor)) static void unloaded(void){
    /* Last line of defence: never leave the cluster on a plane that is going away. */
    alt_ctx_release();
}

__attribute__((constructor)) static void loaded(void){ lg("LOADED v74 pid=%d",(int)getpid()); persist_level_load(); alt_disp_load(); alt_fps_load(); alt_ctx_load(); }
