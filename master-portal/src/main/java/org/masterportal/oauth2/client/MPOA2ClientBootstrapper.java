package org.masterportal.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.loader.AbstractClientBootstrapper;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientBootstrapper;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;

import javax.servlet.ServletContext;

import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/2/15 at  2:01 PM
 */
public class MPOA2ClientBootstrapper extends OA2ClientBootstrapper {
    public static final String MP_OA2_CONFIG_FILE_KEY = "oa4mp:mp-oa2.client.config.file";
    public static final String MP_OA2_CONFIG_NAME_KEY = "oa4mp:mp-oa2.client.config.name";
    public static final String MP_OA2_MYPROXY_CONFIG_NAME_KEY = "org.globus.config.file";

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
        // so this prints out the CILogon client version mostly.
        return new MPOA2ClientLoader(node);
    }
    
    @Override
    public ConfigurationLoader getConfigurationLoader(ServletContext servletContext) throws Exception {
    	
    	String credstoreConfigFile = servletContext.getInitParameter(MP_OA2_MYPROXY_CONFIG_NAME_KEY);
    	if (credstoreConfigFile != null) {
    		System.setProperty(MP_OA2_MYPROXY_CONFIG_NAME_KEY, credstoreConfigFile);
    	} else {
    		throw new MyConfigurationException("No config file specified for myproxy! Pleas specify" + MP_OA2_MYPROXY_CONFIG_NAME_KEY);
    	}
    	
    	return super.getConfigurationLoader(servletContext);
    }
}
