package org.masterportal.oauth2.client;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientBootstrapper;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;

import javax.servlet.ServletContext;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.masterportal.myproxy.CredStoreService;

/*
 *  Bootstraps Master Portal OA4MP Client
 */
public class MPOA2ClientBootstrapper extends OA2ClientBootstrapper {
	
    public static final String MP_OA2_CONFIG_FILE_KEY = "oa4mp:mp-oa2.client.config.file";
    public static final String MP_OA2_CONFIG_NAME_KEY = "oa4mp:mp-oa2.client.config.name";
    //public static final String MP_OA2_MYPROXY_CONFIG_NAME_KEY = "org.globus.config.file";
    //public static final String MP_OA2_MYPROXY_CONFIG_LOG4J = "org.globus.log4j.properties";

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
    	
    	String credstoreConfigFile = servletContext.getInitParameter(CredStoreService.MYPROXY_CONFIG_NAME_KEY);
    	if (credstoreConfigFile != null) {
    		System.setProperty(CredStoreService.MYPROXY_CONFIG_NAME_KEY, credstoreConfigFile);
    	} else {
    		throw new MyConfigurationException("No config file specified for myproxy! Pleas specify" + CredStoreService.MYPROXY_CONFIG_NAME_KEY);
    	}
    	
    	String credstoreLogFile = servletContext.getInitParameter(CredStoreService.MYPROXY_CONFIG_LOG4J);
    	if (credstoreConfigFile != null && !credstoreConfigFile.isEmpty()) {
    		System.setProperty(CredStoreService.MYPROXY_CONFIG_LOG4J, servletContext.getRealPath("/") +  credstoreLogFile);
    	} else {
    		System.err.println("Log4j config file for jglobus (" + CredStoreService.MYPROXY_CONFIG_LOG4J + ") unset! JGlobus will run without logging!" );
    	}
    	
    	return super.getConfigurationLoader(servletContext);
    }
}
