package eu.rcauth.masterportal.client;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.myproxy.MyProxyServiceFacade;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.MyProxyFacadeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.client.DelegationService;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;

import javax.inject.Provider;
import java.net.URI;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * MP Client Service Environment with added support for myproxy connection.
 * <p>
 * Originally, the OA4MP Client does not support/require direct connections
 * to a MyProxy Server. In case of the MP Client, however, we want to be able
 * to store/cache the incoming user certificates in form of a proxy inside a
 * MyProxy Server. This Service Environment builds the appropriate classes
 * for MyProxy support.
 *
 * @author "Tamás Balogh"
 */
public class MPOA2ClientEnvironment extends OA2ClientEnvironment {

    public MPOA2ClientEnvironment(MyLoggingFacade logger, Map<String, String> constants, URI accessTokenUri,
            URI authorizationUri, URI callback, URI initializeURI, URI resourceServerUri, long certLifetime,
            String clientId, String skin, boolean enableAssetCleanup, long maxAssetLifetime, long keypairLifetime,
            AssetProvider assetProvider, Provider<Client> clientProvider, Provider<TokenForge> tokenForgeProvider,
            Provider<DelegationService> delegationServiceProvider, Provider<AssetStore> assetStoreProvider,
            boolean showRedirectPage, boolean requestProxies, String errorPagePath, String redirectPagePath,
            String successPagePath, String secret, Collection<String> scopes, String wellKnownURI, boolean oidcEnabled,
            boolean showIDToken, List<MyProxyFacadeProvider> mfp, String myproxyPassword) {
        super(logger, constants, accessTokenUri, authorizationUri, callback, initializeURI, resourceServerUri,
                certLifetime, clientId, skin, enableAssetCleanup, maxAssetLifetime, keypairLifetime,
                assetProvider, clientProvider, tokenForgeProvider, delegationServiceProvider, assetStoreProvider,
                showRedirectPage, requestProxies, errorPagePath, redirectPagePath, successPagePath, secret, scopes,
                wellKnownURI, oidcEnabled, showIDToken);

        this.mfps = mfp;
        this.myproxyPassword = myproxyPassword;
    }

    /* MYPROXY CONNECTION CONFIGURATION */

    protected final List<MyProxyFacadeProvider> mfps;

    protected List<MyProxyServiceFacade> myProxyServices;

    /**
     * Get the MyProxy Service  which than can be used to talk to a MyProxy Server.
     *
     * @return List of available MyProxy Services.
     */
    public List<MyProxyServiceFacade> getMyProxyServices() {
        if (myProxyServices == null) {
            myProxyServices = new LinkedList<>();
            // loop through each found component
            for (MyProxyFacadeProvider m : mfps) {
                myProxyServices.add(m.get());
            }
            return myProxyServices;
        }
        return myProxyServices;
    }

    protected String myproxyPassword;

    /**
     * Get the configured MyProxy Server password
     *
     * @return the MyProxy Server password
     */
    public String getMyproxyPassword() {
        return myproxyPassword;
    }
}
