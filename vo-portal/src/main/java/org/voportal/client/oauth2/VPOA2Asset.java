package org.voportal.client.oauth2;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.security.core.Identifier;

/*
 * VO Portal Asset extension includes voms_fqan for every transaction asset
 */
public class VPOA2Asset extends OA2Asset {

	String voms_fqan = null;
	
	public VPOA2Asset(Identifier identifier) {
		super(identifier);
	}

	public String getVoms_fqan() {
		return voms_fqan;
	}
	
	public void setVoms_fqan(String voms_fqan) {
		this.voms_fqan = voms_fqan;
	}
	
}
