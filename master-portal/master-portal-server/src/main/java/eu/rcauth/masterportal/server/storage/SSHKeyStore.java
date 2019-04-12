package eu.rcauth.masterportal.server.storage;

import java.util.Collection;
import java.util.List;

import edu.uiuc.ncsa.security.core.Store;
import eu.rcauth.masterportal.server.storage.sql.SQLSSHKeyStore;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 * Basic interface for a store of SSHKey.
 * @see SQLSSHKeyStore
 */
public interface SSHKeyStore<V extends SSHKey> extends Store<V> {

    /** @return current list of all SSHKey. */
    @Override
    Collection<V> values();

    /** @return current list of SSHKey for given username */
    List<SSHKey> getAll(String userName);

    /** adds a new {@link SSHKey} into the store. */
    @Override
    void save(SSHKey value);

    /** updates an existing {@link SSHKey} in the store. */
    @Override
    void update(SSHKey value);

    /** @return {@link SSHKey} from the store. */
    @Override
    V get(Object key);

    /** removes key from store. */
    @Override
    V remove(Object key);

    /** @return whether key is present in store. */
    @Override
    boolean containsKey(Object key);
}
