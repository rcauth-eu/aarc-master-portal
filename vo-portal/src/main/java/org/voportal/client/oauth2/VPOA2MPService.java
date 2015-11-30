package org.voportal.client.oauth2;

import java.util.Map;

import org.voportal.client.ProxyAssetResponse;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.client.request.DelegatedAssetResponse;
import edu.uiuc.ncsa.security.delegation.token.MyX509Proxy;
import edu.uiuc.ncsa.security.oauth_2_0.ProxyOA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.oauth_2_0.client.ProxyDelegationService;

public class VPOA2MPService extends OA2MPService {
	
	
    public static class VPOA2MPProvider extends OA4MPServiceProvider{
        public VPOA2MPProvider(ClientEnvironment clientEnvironment) {
            super(clientEnvironment);
        }

        @Override
        public VPOA2MPService get() {
            return new VPOA2MPService(clientEnvironment);
        }
    }

    protected MyLoggingFacade logger = null;
    
    public VPOA2MPService(ClientEnvironment environment) {
        super(environment);
        
        if (getEnvironment() != null) {
        	logger = getEnvironment().getMyLogger();
        } else {
	        // always return one so even if things blow up some record remains...
	        logger = new MyLoggingFacade("NOENV-VOPortal");
        }
    }
    
    public AssetResponse getProxy(OA2Asset a, ATResponse2 atResponse2) {

    	// The process of including the right CSR in the request has been moved to preGetCert 

        Map<String, String> m1 = getAssetParameters(a);
        preGetCert(a, m1);
        
        ProxyDelegationService proxyService = (ProxyDelegationService) getEnvironment().getDelegationService();
        DelegatedAssetResponse daResp = proxyService.getProxy(atResponse2, getEnvironment().getClient(), m1);

        ProxyAssetResponse par = new ProxyAssetResponse();
        MyX509Proxy myX509Proxy = (MyX509Proxy) daResp.getProtectedAsset();
        par.setX509Certificates(myX509Proxy.getX509Certificates());
        par.setProxyKey(myX509Proxy.getProxyKey());
        par.setProxy(myX509Proxy.getProxy());
        // OAuth 2/OIDC returns this with the access token.
        par.setUsername(daResp.getAdditionalInformation().get("username"));
        
        postGetCert(a, par);
        a.setCertificates(par.getX509Certificates());
        getEnvironment().getAssetStore().save(a);
        return par;
    }
    
    
    @Override
    public void preGetCert(Asset asset, Map parameters) {
    	
    	logger.info("Entering VO Portal GetCert Preprocessing");
    	
    	parameters.put(ProxyOA2Constants.VOMS_FQAN, ((VPOA2Asset)asset).getVoms_fqan());
        
        parameters.put(ProxyOA2Constants.PROXY_LIFETIME, ((VPOA2ClientEnvironment)getEnvironment()).getProxyLifetime());
            	
    	logger.info("Exiting VO Portal GetCert Preprocessing");
    	
    }
    
    @Override
    public void postGetCert(Asset asset, AssetResponse assetResponse) {
    	
    	logger.info("Entering VO Portal GetCert Postprocessing");

    	logger.info("Exiting VO Portal GetCert Postprocessing");
    	
    }

}
