package eu.rcauth.masterportal.server.storage.impl;

import eu.rcauth.masterportal.server.storage.SSHKeyStore;

import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 * Provider class for {@link SSHKeyStore} objects
 */

public abstract class SSHKeyStoreProvider<T extends SSHKeyStore> extends MultiTypeProvider<T> {

    public SSHKeyStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger, String type, String target) {
        super(config, disableDefaultStore, logger, type, target);
    }

}
