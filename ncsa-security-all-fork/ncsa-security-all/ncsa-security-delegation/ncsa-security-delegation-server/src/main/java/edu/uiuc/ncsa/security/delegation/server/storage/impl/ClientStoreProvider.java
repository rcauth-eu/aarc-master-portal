package edu.uiuc.ncsa.security.delegation.server.storage.impl;

import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  10:02 AM
 */
public  abstract class ClientStoreProvider<T extends ClientStore> extends MultiTypeProvider<T> {
    public ClientStoreProvider(ConfigurationNode config,
                               boolean disableDefaultStore, MyLoggingFacade logger, String type, String target) {
        super(config, disableDefaultStore, logger, type, target);
    }
}
