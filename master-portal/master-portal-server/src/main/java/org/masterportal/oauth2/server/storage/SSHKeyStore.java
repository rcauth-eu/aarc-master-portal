package org.masterportal.oauth2.server.storage;

import java.util.List;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;

public interface SSHKeyStore<V extends SSHKey> extends Store<V> {
    public List<SSHKey> getAll();

    public List<SSHKey> getAll(String username);

    public void save(SSHKey value);

    public void update(SSHKey value);

    // get(Object) already defined in Map (hence in Store) as V get(Object)
//    public SSHKey get(Object key);

    // remove(Object) already defined in Map (hence in Store) as V remove(Object)
//    public SSHKey remove(Object key);

    public boolean containsKey(Object key);
}
