package org.masterportal.server.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionKeys;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.MyX509Proxy;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;

public class MPOA2TConverter<V extends OA2ServiceTransaction> extends OA2TConverter<V> {

	public MPOA2TConverter(OA2TransactionKeys keys, IdentifiableProvider<V> identifiableProvider, TokenForge tokenForge,
			ClientStore<? extends Client> cs) {
		super(keys, identifiableProvider, tokenForge, cs);
	}
	
	@Override
	public V fromMap(ConversionMap<String, Object> map, V v) {
		
		String proxy = map.getString(getDSTK().cert());
		map.remove(getDSTK().cert());
		
		V t = super.fromMap(map, v);
		
		if (proxy != null && !proxy.isEmpty()) {
			MyX509Proxy proxyCert = new MyX509Proxy(proxy.getBytes());
			t.setProtectedAsset(proxyCert);
		}
		map.put(getDSTK().cert(), proxy);
		
		return t;
	}
	
	@Override
	public void toMap(V t, ConversionMap<String, Object> map) {
		super.toMap(t, map);
		
		map.remove(getDSTK().cert());
		
		MyX509Proxy myProxy = (MyX509Proxy) t.getProtectedAsset();
        if (myProxy == null || myProxy.getProxy() == null) {
            map.put(getDSTK().cert(), null);
        } else {
			map.put(getDSTK().cert(), new String(myProxy.getProxy()));
        }		
		
	}
	
	
}
