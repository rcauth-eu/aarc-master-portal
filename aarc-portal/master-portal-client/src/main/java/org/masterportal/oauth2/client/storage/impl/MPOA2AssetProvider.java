package org.masterportal.oauth2.client.storage.impl;

import org.masterportal.oauth2.client.MPOA2Asset;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2AssetProvider;
import edu.uiuc.ncsa.security.core.Identifier;

public class MPOA2AssetProvider<V extends MPOA2Asset> extends OA2AssetProvider<V> {

	@Override
	public Asset get(Identifier identifier) {
		return new MPOA2Asset(identifier);
	}
	
}
