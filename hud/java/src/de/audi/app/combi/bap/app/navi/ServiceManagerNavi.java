package de.audi.app.combi.bap.app.navi;

import de.audi.app.bap.fw.AbstractBAPModuleServiceManager;
import de.audi.app.combi.bap.fw.AbstractCombiModule;
import de.audi.atip.activator.AbstractActivator;
import de.audi.atip.base.AppNameConst;
import de.audi.atip.interapp.ExternalKeyListener;
import de.audi.atip.interapp.combi.bap.navi.CombiBAPServiceNaviListener;
import de.audi.atip.log.LogChannel;
import java.util.Dictionary;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.util.tracker.ServiceTracker;

/*
 * Shadow of the stock MU1416 class (hmi.jar, 108 lines decompiled).
 *
 * Behaviour is identical to stock, with exactly one addition at the end of
 * registerServices(): the AppConnectorNavi instance - the object the stock
 * navigation already uses to drive the cluster and HUD arrows over BAP - is
 * handed to de.carplay.hud.HudBridge. The call is wrapped so that nothing in
 * the bridge can ever break stock registration.
 *
 * The synthetic class$() lookups of the decompile are replaced by the same
 * interface names as string constants; registerService() only uses getName().
 *
 * Revert: delete carplay_hud.jar from /mnt/app/eso/hmi/lsd/jars and reboot.
 */
public class ServiceManagerNavi extends AbstractBAPModuleServiceManager {
    private static final String SVC_NAVI =
        "de.audi.atip.interapp.combi.bap.navi.CombiBAPServiceNavi";
    private static final String SVC_MSG = "de.audi.atip.msg.MsgListener";
    private static final String SVC_NAVI_LISTENER =
        "de.audi.atip.interapp.combi.bap.navi.CombiBAPServiceNaviListener";
    private static final String SVC_SWDIAG = "de.audi.atip.diag.sw.SwDiagnosisManager";

    private final LogChannel logChannel;

    public ServiceManagerNavi(AbstractCombiModule abstractCombiModule, BundleContext bundleContext) {
        super(abstractCombiModule, bundleContext);
        this.logChannel = abstractCombiModule.getLogChannel();
    }

    public Object addingService(ServiceReference serviceReference) {
        Object service = this.bundleContext.getService(serviceReference);
        if (service instanceof CombiBAPServiceNaviListener) {
            this.logChannel.log(10000000, "[ServiceManagerNavi#addingService] CombiBAPServiceNaviListener found");
            ((AppConnectorNavi) this.module.getAppConnectors().get(AppNameConst.APP_NAME_NAVI))
                .setAppServiceListener((CombiBAPServiceNaviListener) service);
            return service;
        }
        if (!(service instanceof ExternalKeyListener)) {
            this.bundleContext.ungetService(serviceReference);
            return super.addingService(serviceReference);
        }
        this.logChannel.log(10000000, "[ServiceManagerNavi#addingService] ExternalKeyListener found");
        ((CombiModuleNavi) this.module).setExternalKeyListener((ExternalKeyListener) service);
        return service;
    }

    public void removedService(ServiceReference serviceReference, Object obj) {
        if (!(obj instanceof CombiBAPServiceNaviListener)) {
            super.removedService(serviceReference, obj);
            return;
        }
        this.logChannel.log(10000000, "[ServiceManagerNavi#removedService] CombiBAPServiceNaviListener removed");
        ((AppConnectorNavi) this.module.getAppConnectors().get(AppNameConst.APP_NAME_NAVI))
            .setAppServiceListener(null);
        this.bundleContext.ungetService(serviceReference);
    }

    public void registerServices(AbstractActivator abstractActivator) {
        this.logChannel.log(10000000, "[ServiceManagerNavi#registerServices] Registering AppConnectorNavi as CombiBAPServiceNavi");
        Object navi = this.module.getAppConnectors().get(AppNameConst.APP_NAME_NAVI);
        abstractActivator.registerService(SVC_NAVI, navi, (Dictionary) null);
        this.logChannel.log(10000000, "[ServiceManagerNavi#registerServices] Registering InitializationManagerNavi as MessageListener");
        abstractActivator.registerService(SVC_MSG, this.module.getInitializationManager(), (Dictionary) null);

        /* the only addition to stock */
        try {
            de.carplay.hud.HudBridge.start(navi);
        } catch (Throwable t) {
            /* never let the bridge affect stock navigation */
        }
    }

    public void trackServices() {
        String[] names = new String[] { SVC_NAVI_LISTENER, SVC_SWDIAG };
        this.serviceTracker = new ServiceTracker(this.bundleContext, names, this);
        this.serviceTracker.open();
    }
}
