package org.masterportal.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientLoader;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/2/15 at  2:01 PM
 */
public class MPOA2ClientLoader extends OA2ClientLoader {
	
    @Override
    public OA4MPServiceProvider getServiceProvider() {
        return new MPOA2MPService.MPOA2MPProvider(load());
    }	
	
    public MPOA2ClientLoader(ConfigurationNode node) {
        super(node);
    }

    @Override
    public String getVersionString() {
        return "CILogon OAuth2/OIDC client configuration loader version " + VERSION_NUMBER;
    }


}
