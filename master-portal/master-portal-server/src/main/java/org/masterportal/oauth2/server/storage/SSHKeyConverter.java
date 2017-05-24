package org.masterportal.oauth2.server.storage;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

public class SSHKeyConverter<V extends SSHKey> extends MapConverter<V> {

    public SSHKeyConverter(IdentifiableProvider<V> identifiableProvider) {
        super(new SSHKeyKeys(), identifiableProvider);
    }
	
    public SSHKeyConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
	super(keys, provider);
    }

    private SSHKeyKeys getSKKeys() {
	return (SSHKeyKeys) keys;
    }
    
    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
	v = super.fromMap(map, v);
	
	v.setLabel( map.getString( getSKKeys().label()) );
	v.setUserName( map.getString( getSKKeys().username()) );
	v.setPubKey( map.getString( getSKKeys().pub_key()) );
	v.setDescription( map.getString( getSKKeys().description()) );
	return v;
    }
    
    @Override
    public void toMap(V v, ConversionMap<String, Object> map) {
	super.toMap(v, map);
	map.put( getSKKeys().label() , v.getLabel());
	map.put( getSKKeys().username() , v.getUserName());
	map.put( getSKKeys().pub_key() , v.getPubKey());
	map.put( getSKKeys().description() , v.getDescription());
    }
}
