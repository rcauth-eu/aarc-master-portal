package org.masterportal.oauth2.server.storage;

import org.masterportal.oauth2.server.MPOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;

public class MPOA2TConverter<V extends MPOA2ServiceTransaction> extends OA2TConverter<V> {

    public MPOA2TConverter(MPOA2TransactionKeys keys, IdentifiableProvider<V> identifiableProvider, TokenForge tokenForge, ClientStore<? extends Client> cs) {
        super(keys, identifiableProvider, tokenForge, cs);
    }
	
    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
    	V st = super.fromMap(map, v);
    	
    	MPOA2TransactionKeys tck = (MPOA2TransactionKeys) getTCK();

   		st.setMPClientSessionIdentifier( map.getString(tck.mp_client_session_identifier) );
    	
    	return st;
    }

    
    @Override
    public void toMap(V t, ConversionMap<String, Object> map) {
    	super.toMap(t, map);
    	
    	MPOA2TransactionKeys tck = (MPOA2TransactionKeys) getTCK();
 
    	if (t.getMPClientSessionIdentifier() != null) {    		
    		map.put(tck.mp_client_session_identifier, t.getMPClientSessionIdentifier());
    	}
    }
    
}
