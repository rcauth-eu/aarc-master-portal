package org.masterportal.server.oauth2;

import javax.servlet.ServletContext;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.masterportal.myproxy.CredStoreService;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2Bootstrapper;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;

public class MPOA2ServerBootstrapper extends OA2Bootstrapper {

	@Override
	public ConfigurationLoader getConfigurationLoader(ConfigurationNode node) throws MyConfigurationException {
		return new MPOA2ServerLoader(node);
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
