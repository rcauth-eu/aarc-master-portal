package org.voportal.oauth2.client;

import org.apache.commons.configuration.tree.ConfigurationNode;

import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientLoader;


/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/2/15 at  2:01 PM
 */
public class VPOA2ClientLoader extends OA2ClientLoader {
	
    public VPOA2ClientLoader(ConfigurationNode node) {
        super(node);
    }

    @Override
    public String getVersionString() {
        return "VO Portal OAuth2/OIDC client configuration loader version " + VERSION_NUMBER;
    }

}
