package org.masterportal.oauth2.client;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.security.core.Identifier;

/*
 * Master Portal Asset extension includes voms_fqan for every transaction asset
 */
public class MPOA2Asset extends OA2Asset {

	String voms_fqan;
	
	public MPOA2Asset(Identifier identifier) {
		super(identifier);
	}

	public String getVoms_fqan() {
		return voms_fqan;
	}
	
	public void setVoms_fqan(String voms_fqan) {
		this.voms_fqan = voms_fqan;
	}
	
}
