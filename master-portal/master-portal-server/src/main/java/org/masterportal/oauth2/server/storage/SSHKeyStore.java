package org.masterportal.oauth2.server.storage;

import java.util.Collection;
import java.util.List;

import edu.uiuc.ncsa.security.core.Store;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 * Basic interface for a store of SSHKey.
 * @see SQLSSHKeyStore
 */
public interface SSHKeyStore<V extends SSHKey> extends Store<V> {

    /** @return current list of all SSHKey. */
    @Override
    public Collection<V> values();

    /** @return current list of SSHKey for given username */
    public List<SSHKey> getAll(String userName);

    /** adds a new {@link SSHKey} into the store. */
    @Override
    public void save(SSHKey value);

    /** updates an existing {@link SSHKey} in the store. */
    @Override
    public void update(SSHKey value);

    /** @return {@link SSHKey} from the store. */
    @Override
    public V get(Object key);

    /** removes key from store. */
    @Override
    public V remove(Object key);

    /** @return whether key is present in store. */
    @Override
    public boolean containsKey(Object key);
}
