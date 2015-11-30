package org.voportal.client.oauth2;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.client.DelegationService;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;

import javax.inject.Provider;
import java.net.URI;
import java.util.Collection;
import java.util.Map;

public class VPOA2ClientEnvironment extends OA2ClientEnvironment {

    public VPOA2ClientEnvironment(MyLoggingFacade logger, Map<String, String> constants,
            URI accessTokenUri,
            URI authorizationUri,
            URI callback,
            URI initializeURI,
            URI resourceServerUri,
            long certLifetime,
            long proxyLifetime,
            String clientId,
            String skin,
            boolean enableAssetCleanup,
            long maxAssetLifetime,
            long keypairLifetime,
            AssetProvider assetProvider,
            Provider<Client> clientProvider,
            Provider<TokenForge> tokenForgeProvider,
            Provider<DelegationService> delegationServiceProvider,
            Provider<AssetStore> assetStoreProvider,
            boolean showRedirectPage,
            String errorPagePath,
            String redirectPagePath,
            String successPagePath,
            String secret,
            Collection<String> scopes) {
    	
    	super(logger, 
    		  constants, 
    		  accessTokenUri, 
    		  authorizationUri, 
    		  callback, 
    		  initializeURI, 
    		  resourceServerUri, 
    		  certLifetime, 
    		  clientId, 
    		  skin, 
    		  enableAssetCleanup, 
    		  maxAssetLifetime, 
    		  keypairLifetime, 
    		  assetProvider, 
    		  clientProvider, 
    		  tokenForgeProvider, 
    		  delegationServiceProvider, 
    		  assetStoreProvider, 
    		  showRedirectPage, 
    		  errorPagePath, 
    		  redirectPagePath, 
    		  successPagePath, 
    		  secret, 
    		  scopes);
    	
    	this.proxyLifetime = proxyLifetime;
    	
    }
	
    
    protected long proxyLifetime = 0L;
    
    public long getProxyLifetime() {
		return proxyLifetime;
	}
    
    public void setProxyLifetime(long proxyLifetime) {
		this.proxyLifetime = proxyLifetime;
	}
}
