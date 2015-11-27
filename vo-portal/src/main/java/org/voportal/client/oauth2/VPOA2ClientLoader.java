package org.voportal.client.oauth2;

import java.net.URI;

import javax.inject.Provider;

import org.apache.commons.configuration.tree.ConfigurationNode;

import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientLoader;
import edu.uiuc.ncsa.security.delegation.client.DelegationService;
import edu.uiuc.ncsa.security.oauth_2_0.client.AGServer2;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATServer2;
import edu.uiuc.ncsa.security.oauth_2_0.client.DS2;
import edu.uiuc.ncsa.security.oauth_2_0.client.PAServer2;
import edu.uiuc.ncsa.security.oauth_2_0.client.PPServer2;
import edu.uiuc.ncsa.security.oauth_2_0.client.ProxyDelegationService;
import edu.uiuc.ncsa.security.oauth_2_0.client.RTServer2;
import edu.uiuc.ncsa.security.oauth_2_0.client.UIServer2;


/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/2/15 at  2:01 PM
 */
public class VPOA2ClientLoader extends OA2ClientLoader {

	public static final String PROXY_ASSET_ENDPOINT = "getproxy";
	
    public VPOA2ClientLoader(ConfigurationNode node) {
        super(node);
    }

    @Override
    public String getVersionString() {
        return "VO Portal OAuth2/OIDC client configuration loader version " + VERSION_NUMBER;
    }
    
    
    @Override
    public OA4MPServiceProvider getServiceProvider() {
    	return new VPOA2MPService.VPOA2MPProvider(load());
    }

    @Override
    protected Provider getDSP() {
    	
        if (dsp == null) {
            dsp = new Provider<DelegationService>() {
                @Override
                public DelegationService get() {
                    return new ProxyDelegationService(new AGServer2(createServiceClient(getAuthzURI())), // as per spec, request for AG comes through authz endpoint.
                            new ATServer2(createServiceClient(getAccessTokenURI())),
                            new PAServer2(createServiceClient(getAssetURI())),
                            new UIServer2(createServiceClient(getUIURI())),
                            new RTServer2(createServiceClient(getAccessTokenURI())), // as per spec, refresh token server is at same endpoint as access token server.
                            new PPServer2(createServiceClient(getProxyAssetURI()))
                    );
                }
            };
        }
        
        return dsp;
    }
    
    protected URI getProxyAssetURI() {
        String x = getCfgValue(VPClientXMLTags.PROXY_ASSET_URI);
        checkProtocol(x);
        return createServiceURI(x, getBaseURI(), PROXY_ASSET_ENDPOINT);
    }   
    
    
}
