package org.masterportal.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2AssetConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

public class MPOA2AssetConverter extends OA2AssetConverter {

	public MPOA2AssetConverter(SerializationKeys keys, IdentifiableProvider<Asset> provider) {
		super(keys, provider);
	}
	
    MPOA2AssetSerializationKeys getASK() {
        return (MPOA2AssetSerializationKeys) keys;
    }	

	@Override
	public Asset fromMap(ConversionMap<String, Object> map, Asset asset) {
		MPOA2Asset a = (MPOA2Asset) super.fromMap(map,asset);
		
		a.setRequest_state(map.getString(getASK().request_state));
		a.setRequest_code(map.getString(getASK().request_code));
		
		return a;
	}
	
	@Override
	public void toMap(Asset asset, ConversionMap<String, Object> map) {
		super.toMap(asset, map);
		
		MPOA2Asset a = (MPOA2Asset) super.fromMap(map,asset);

		if (a.getRequest_code() != null) {
			map.put(getASK().request_code(), a.getRequest_code());
		}
		if (a.getRequest_state() != null) {
			map.put(getASK().request_state(), a.getRequest_state());
		}		
	}
	
}
