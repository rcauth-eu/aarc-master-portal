package eu.rcauth.masterportal.server.storage.sql;


import eu.rcauth.masterportal.servlet.MPOA4MPConfigTags;
import eu.rcauth.masterportal.server.storage.SSHKey;
import eu.rcauth.masterportal.server.storage.SSHKeyKeys;
import eu.rcauth.masterportal.server.storage.sql.table.SSHKeyTable;

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

    // Note: this one is currently not being used it seems
    public SQLSSHKeyStoreProvider(
            ConfigurationNode config,
            ConnectionPoolProvider<? extends ConnectionPool> cpp,
            String type,
            String target,
            String tablename,
            MapConverter<SSHKey> converter,
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

    // Note we suppress an unchecked cast to T
    @Override
    @SuppressWarnings("unchecked")
    public V newInstance(Table table) {
    	return (V) new SQLSSHKeyStore(getConnectionPool(), table, sshKeyProvider, converter);
    }
    
    @Override
    public V get() {
    	return newInstance( new SSHKeyTable( (SSHKeyKeys) converter.keys, getSchema(), getPrefix(), getTablename()));
    }
    
}
