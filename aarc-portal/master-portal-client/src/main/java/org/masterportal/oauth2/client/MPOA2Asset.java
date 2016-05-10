package org.masterportal.oauth2.client;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.security.core.Identifier;

/*
 * Master Portal Asset extension includes the original request 
 * code & status as a session identifier for the MP Server Component.
 */
public class MPOA2Asset extends OA2Asset {

	public MPOA2Asset(Identifier identifier) {
		super(identifier);
	}
	
	String MPServerRequestState;
	String MPServerRequestCode;
	
	public String getMPServerRequestState() {
		return MPServerRequestState;
	}
	
	public String getMPServerRequestCode() {
		return MPServerRequestCode;
	}
	
	public void setMPServerRequestState(String request_state) {
		this.MPServerRequestState = request_state;
	}
	
	public void setMPServerRequestCode(String request_code) {
		this.MPServerRequestCode = request_code;
	}
	
}
