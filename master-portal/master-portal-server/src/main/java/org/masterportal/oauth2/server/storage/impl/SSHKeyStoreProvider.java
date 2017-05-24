package org.masterportal.oauth2.server.storage.impl;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.masterportal.oauth2.server.storage.SSHKeyStore;

import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

public abstract class SSHKeyStoreProvider<T extends SSHKeyStore> extends MultiTypeProvider<T> {

    public SSHKeyStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger, String type, String target) {
    	super(config, disableDefaultStore, logger, type, target);
    }
	
}
