package org.masterportal.oauth2.client.storage;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.security.core.Identifier;

/*
 * Master Portal Asset extension includes voms_fqan for every transaction asset
 */
public class MPOA2Asset extends OA2Asset {

	public MPOA2Asset(Identifier identifier) {
		super(identifier);
	}
	
	String request_state;
	String request_code;
	
	public String getRequest_state() {
		return request_state;
	}
	
	public String getRequest_code() {
		return request_code;
	}
	
	public void setRequest_state(String request_state) {
		this.request_state = request_state;
	}
	
	public void setRequest_code(String request_code) {
		this.request_code = request_code;
	}
	
}
