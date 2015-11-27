package org.voportal.client.oauth2;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.security.core.Identifier;

public class VPOA2AssetProvider<V extends VPOA2Asset> extends AssetProvider<V> {

	@Override
	public Asset get(Identifier identifier) {
		return new VPOA2Asset(identifier);
	}
	
}
