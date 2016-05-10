package org.masterportal.oauth2.client.loader;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientBootstrapper;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;

import javax.servlet.ServletContext;

import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 *  Bootstraps Master Portal OA4MP Client
 *  
 *  @author Tamás Balogh
 */
public class MPOA2ClientBootstrapper extends OA2ClientBootstrapper {
	
    public static final String MP_OA2_CONFIG_FILE_KEY = "oa4mp:mp-oa2.client.config.file";
    public static final String MP_OA2_CONFIG_NAME_KEY = "oa4mp:mp-oa2.client.config.name";

    @Override
    public String getOa4mpConfigFileKey() {
        return MP_OA2_CONFIG_FILE_KEY;
    }

    @Override
    public String getOa4mpConfigNameKey() {
        return MP_OA2_CONFIG_NAME_KEY;
    }

    @Override
    public ConfigurationLoader getConfigurationLoader(ConfigurationNode node) throws MyConfigurationException {
        return new MPOA2ClientLoader(node);
    }
    
    @Override
    public ConfigurationLoader getConfigurationLoader(ServletContext servletContext) throws Exception {
    	return super.getConfigurationLoader(servletContext);
    }
}
