package org.voportal.client.oauth2;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientBootstrapper;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;

import org.apache.commons.configuration.tree.ConfigurationNode;

/*
 *  Bootstraps VO Portal OA4MP Client
 */
public class VPOA2ClientBootstrapper extends OA2ClientBootstrapper {
	
    public static final String VP_OA2_CONFIG_FILE_KEY = "oa4mp:vp-oa2.client.config.file";
    public static final String VP_OA2_CONFIG_NAME_KEY = "oa4mp:vp-oa2.client.config.name";

    @Override
    public String getOa4mpConfigFileKey() {
        return VP_OA2_CONFIG_FILE_KEY;
    }

    @Override
    public String getOa4mpConfigNameKey() {
        return VP_OA2_CONFIG_NAME_KEY;
    }

    @Override
    public ConfigurationLoader getConfigurationLoader(ConfigurationNode node) throws MyConfigurationException {
        return new VPOA2ClientLoader(node);
    }
    
}
