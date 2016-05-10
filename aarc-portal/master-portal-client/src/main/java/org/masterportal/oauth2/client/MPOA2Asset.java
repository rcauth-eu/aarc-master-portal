package org.masterportal.oauth2.client;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.security.core.Identifier;

/**
 * MP Client Asset extension includes the original request 
 * code & status as a session identifier for the MP Server Component.
 * This session identifier (code & status) is sent back to the 
 * MP Server once authentication has completed in order to 
 * identify the ongoing session.
 * 
 * @author "Tamás Balogh"
 *
 */
public class MPOA2Asset extends OA2Asset {

	public MPOA2Asset(Identifier identifier) {
		super(identifier);
	}
	
	String MPServerRequestState;
	String MPServerRequestCode;
	
	/* GETTERS AND SETTERS */
	
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
