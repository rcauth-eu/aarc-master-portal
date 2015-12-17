package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPService;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;

/**
 * Service provider for the OA4MP service.
 * <p>Created by Jeff Gaynor<br>
 * on 2/25/14 at  10:17 AM
 * 
 * Modified by Tamas Balogh
 * Create a MPProxyService instance in case this client is going to
 * be used to request proxies instead of certificates
 */
public class OA2MPServiceProvider extends OA4MPServiceProvider {
    public OA2MPServiceProvider(ClientEnvironment OA2ClientEnvironment) {
        super(OA2ClientEnvironment);
    }

    @Override
    public OA4MPService get() {
    	
    	if ( ((OA2ClientEnvironment)clientEnvironment).isRequestProxies() ) {
    		return new OA2MPProxyService(clientEnvironment);
    	} else {
    		return new OA2MPService(clientEnvironment);
    	}
    	
    }
}
