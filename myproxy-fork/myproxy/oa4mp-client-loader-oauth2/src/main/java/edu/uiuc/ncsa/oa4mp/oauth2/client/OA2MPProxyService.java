package edu.uiuc.ncsa.oa4mp.oauth2.client;

import java.util.Map;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.security.delegation.client.request.DelegatedAssetResponse;
import edu.uiuc.ncsa.security.delegation.token.MyX509Proxy;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;

public class OA2MPProxyService extends OA2MPService {

    public OA2MPProxyService(ClientEnvironment environment) {
        super(environment);
    }	
	
    public AssetResponse getProxy(OA2Asset a, ATResponse2 atResponse2) {

        Map<String, String> m1 = getAssetParameters(a);
        
        preGetProxy(a, m1);
        
        DelegatedAssetResponse daResp = getEnvironment().getDelegationService().getCert(atResponse2, getEnvironment().getClient(), m1);

        AssetResponse par = new AssetResponse();
        MyX509Proxy myX509Proxy = (MyX509Proxy) daResp.getProtectedAsset();
        
        par.setCredential(myX509Proxy);
        
        // OAuth 2/OIDC returns this with the access token.
        par.setUsername(daResp.getAdditionalInformation().get("username"));
        
        postGetProxy(a, par);
        
        a.setCertificates(par.getX509Certificates());
        getEnvironment().getAssetStore().save(a);
        
        return par;
    }    
    
    public void preGetProxy(Asset asset, Map parameters) {
    	
    	// add VO related request parameters 
    	OA2Asset a = ((OA2Asset)asset);
    	String voname = a.getVoname();
    	if ( voname != null && !voname.isEmpty() ) {
    		parameters.put(OA2Constants.VONAME, voname);
    	}
    	String vomses = a.getVomses();
    	if ( vomses != null && !vomses.isEmpty() ) {
    		parameters.put(OA2Constants.VOMSES, vomses);
    	}    	
    	
    	//should proxylifetime get a dedicated config parameter in the client.cfg? 
        parameters.put(OA2Constants.PROXY_LIFETIME, getEnvironment().getCertLifetime());
        
    }
    
    
    public void postGetProxy(Asset asset, AssetResponse assetResponse) {

    }
    
}
