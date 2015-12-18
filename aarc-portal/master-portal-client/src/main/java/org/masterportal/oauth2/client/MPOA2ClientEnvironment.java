package org.masterportal.oauth2.client;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.myproxy.MyProxyServiceFacade;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.MyProxyFacadeProvider;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
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

public class MPOA2ClientEnvironment extends OA2ClientEnvironment {

	public MPOA2ClientEnvironment(URI accessTokenUri, URI authorizationUri, URI callback, long certLifetime,
			String clientId, DelegationService delegationService, URI resourceServerUri, TokenForge tokenForge,
			AssetStore assetStore, boolean showRedirectPage, String errorPagePath, String redirectPagePath,
			String successPagePath) {
		super(accessTokenUri, authorizationUri, callback, certLifetime, clientId, delegationService,
				resourceServerUri, tokenForge, assetStore, showRedirectPage, errorPagePath, redirectPagePath,
				successPagePath);
	}

	public MPOA2ClientEnvironment(MyLoggingFacade logger, Map<String, String> constants, URI accessTokenUri,
			URI authorizationUri, URI callback, URI initializeURI, URI resourceServerUri, long certLifetime,
			String clientId, String skin, boolean enableAssetCleanup, long maxAssetLifetime, long keypairLifetime,
			AssetProvider assetProvider, Provider<Client> clientProvider, Provider<TokenForge> tokenForgeProvider,
			Provider<DelegationService> delegationServiceProvider, Provider<AssetStore> assetStoreProvider,
			boolean showRedirectPage, boolean requestProxies, String errorPagePath, String redirectPagePath,
			String successPagePath, String secret, Collection<String> scopes) {
		super(logger, constants, accessTokenUri, authorizationUri, callback, initializeURI, resourceServerUri,
				certLifetime, clientId, skin, enableAssetCleanup, maxAssetLifetime, keypairLifetime,
				assetProvider, clientProvider, tokenForgeProvider, delegationServiceProvider, assetStoreProvider,
				showRedirectPage, requestProxies, errorPagePath, redirectPagePath, successPagePath, secret, scopes);
	}
	
	public MPOA2ClientEnvironment(MyLoggingFacade logger, Map<String, String> constants, URI accessTokenUri,
			URI authorizationUri, URI callback, URI initializeURI, URI resourceServerUri, long certLifetime,
			String clientId, String skin, boolean enableAssetCleanup, long maxAssetLifetime, long keypairLifetime,
			AssetProvider assetProvider, Provider<Client> clientProvider, Provider<TokenForge> tokenForgeProvider,
			Provider<DelegationService> delegationServiceProvider, Provider<AssetStore> assetStoreProvider,
			boolean showRedirectPage, boolean requestProxies, String errorPagePath, String redirectPagePath,
			String successPagePath, String secret, Collection<String> scopes, List<MyProxyFacadeProvider> mfp, String myproxyPassword) {
		super(logger, constants, accessTokenUri, authorizationUri, callback, initializeURI, resourceServerUri,
				certLifetime, clientId, skin, enableAssetCleanup, maxAssetLifetime, keypairLifetime,
				assetProvider, clientProvider, tokenForgeProvider, delegationServiceProvider, assetStoreProvider,
				showRedirectPage, requestProxies, errorPagePath, redirectPagePath, successPagePath, secret, scopes);
		
		this.mfps = mfp;
		this.myproxyPassword = myproxyPassword;
	}	

	
    protected List<MyProxyFacadeProvider> mfps;

    protected List<MyProxyServiceFacade> myProxyServices;

    public List<MyProxyServiceFacade> getMyProxyServices() {
        if (myProxyServices == null) {
            myProxyServices = new LinkedList<MyProxyServiceFacade>();
            // loop through each found component
            for (MyProxyFacadeProvider m : mfps) {
                myProxyServices.add(m.get());
            }
            return myProxyServices;
        }
        return myProxyServices;
    }
    
    protected String myproxyPassword;
    
    public void setMyproxyPassword(String myproxyPassword) {
		this.myproxyPassword = myproxyPassword;
	}
    
    public String getMyproxyPassword() {
		return myproxyPassword;
	}
}
