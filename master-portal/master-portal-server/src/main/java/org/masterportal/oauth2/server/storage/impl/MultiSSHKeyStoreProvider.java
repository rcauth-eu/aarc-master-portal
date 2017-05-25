package org.masterportal.oauth2.server.storage.impl;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.masterportal.oauth2.server.storage.SSHKey;
import org.masterportal.oauth2.server.storage.SSHKeyStore;

import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

public class MultiSSHKeyStoreProvider<T extends SSHKey> extends SSHKeyStoreProvider<SSHKeyStore<T>> {

    public MultiSSHKeyStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger, String type, String target) {
    	super(config, disableDefaultStore, logger, type, target);
    }

    @Override
    public SSHKeyStore<T> getDefaultStore() {
	throw new NotImplementedException("SSHKeyStoreProvider does not have a default store. Yet.");
    }
}
