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
		
		a.setVoms_fqan(map.getString(getASK().voms_fqan()));
		
		return a;
	}
	
	@Override
	public void toMap(Asset asset, ConversionMap<String, Object> map) {
		super.toMap(asset, map);
		
		MPOA2Asset a = (MPOA2Asset) super.fromMap(map,asset);
		
		if (a.getVoms_fqan() != null) {
			map.put(getASK().voms_fqan(), a.getVoms_fqan());
		}
	}
	
}
