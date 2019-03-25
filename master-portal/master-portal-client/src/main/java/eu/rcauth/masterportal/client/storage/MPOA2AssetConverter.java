package eu.rcauth.masterportal.client.storage;

import eu.rcauth.masterportal.client.MPOA2Asset;

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
		
		a.setMPServerRequestState(map.getString(getASK().mp_server_request_state()));
		a.setMPServerRequestCode(map.getString(getASK().mp_server_request_code()));
		
		return a;
	}
	
	@Override
	public void toMap(Asset asset, ConversionMap<String, Object> map) {
		super.toMap(asset, map);

		MPOA2Asset a = (MPOA2Asset) asset;
		
		String reqCode = a.getMPServerRequestCode();
		if (reqCode != null && !reqCode.isEmpty()) {
			map.put(getASK().mp_server_request_code(), reqCode);
		}
		
		String reqState = a.getMPServerRequestState();
		if (reqState != null && !reqState.isEmpty()) {
			map.put(getASK().mp_server_request_state(), reqState);
		}	
		
		// remove the private key from the map, so that it will never get serialized
		map.remove( getASK().privateKey() );
		
	}
	
}
