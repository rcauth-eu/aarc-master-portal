package org.masterportal.oauth2.server.storage.sql;


import org.masterportal.oauth2.servlet.MPOA4MPConfigTags;
import org.masterportal.oauth2.server.storage.SSHKey;
import org.masterportal.oauth2.server.storage.SSHKeyKeys;
import org.masterportal.oauth2.server.storage.sql.table.SSHKeyTable;

import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 * Provider class for (@link SQLSSHKeyStore} objects.
 */

public class SQLSSHKeyStoreProvider<V extends SQLSSHKeyStore> extends SQLStoreProvider<V> {

    protected Provider<SSHKey> sshKeyProvider;
	
    public SQLSSHKeyStoreProvider(
            ConfigurationNode config,
            ConnectionPoolProvider<? extends ConnectionPool> cpp,
            String type,
            String target,
            String tablename,
            MapConverter converter,
            Provider<SSHKey> provider) {
        super(config, cpp, type, target, tablename, converter);
        this.sshKeyProvider = provider;
    }

    public SQLSSHKeyStoreProvider(
            ConfigurationNode config,
            ConnectionPoolProvider<? extends ConnectionPool> cpp,
            String type,
            MapConverter converter,
            Provider<SSHKey> provider) {
        super(config, cpp, type, MPOA4MPConfigTags.SSH_KEY_STORE, SQLSSHKeyStore.DEFAULT_TABLENAME, converter);
        this.sshKeyProvider = provider;
    }
     
    @Override
    public V newInstance(Table table) {
    	return (V) new SQLSSHKeyStore(getConnectionPool(), table, sshKeyProvider, converter);
    }
    
    @Override
    public V get() {
    	return newInstance( new SSHKeyTable( (SSHKeyKeys) converter.keys, getSchema(), getPrefix(), getTablename()));
    }
    
}
