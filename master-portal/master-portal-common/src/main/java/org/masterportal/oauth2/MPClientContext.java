package org.masterportal.oauth2;


public interface MPClientContext {

	// This value should correspond to the Master Portal OA4MP Client root context.
	// This is derived from the deployment war name taken from the client pom.xml
	public static final String MP_CLIENT_CONTEXT = "/mp-oa2-client";
	
	/*
	 *  /startRequest  
	 */
	
	public static final String MP_CLIENT_START_ENDPOINT = "/startRequest";
	// Variable used to identify client session from cookies. 
	// Matches edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.OA4MP_CLIENT_REQUEST_ID  
	public static final String MP_CLIENT_REQUEST_ID = "oa4mp_client_req_id";
	
	/*
	 *  /forwardgetcert
	 */
	public static final String MP_CLIENT_FWGETCERT_ENDPOINT = "/forwardgetcert";
	
}
