package eu.rcauth.masterportal.server.storage.impl;

import eu.rcauth.masterportal.server.storage.SSHKey;
import eu.rcauth.masterportal.server.storage.SSHKeyStore;

import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 * a {@link SSHKeyStoreProvider} without a default store.
 */
public class MultiSSHKeyStoreProvider<T extends SSHKey> extends SSHKeyStoreProvider<SSHKeyStore<T>> {

    public MultiSSHKeyStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger, String type, String target) {
        super(config, disableDefaultStore, logger, type, target);
    }

    @Override
    public SSHKeyStore<T> getDefaultStore() {
        throw new NotImplementedException("SSHKeyStoreProvider does not have a default store. Yet.");
    }
}
