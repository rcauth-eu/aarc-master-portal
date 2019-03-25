package eu.rcauth.masterportal;


public interface MPServerContext {

	// This value should correspond to the Master Portal OA4MP Server root context.
	// This is derived from the deployment war name taken from the client pom.xml	
	public static final String MP_SERVER_CONTEXT = "/mp-oa2-server";
	
	/*
	 *  /authorize
	 */
	
	public static final String MP_SERVER_AUTHORIZE_ENDPOINT = "/authorize";
	
	// parameters expected when calling the /authorize endpoint after successful authentication
	public static final String MP_SERVER_AUTHORIZE_CODE = "code";
	public static final String MP_SERVER_AUTHORIZE_STATE = "state";
	public static final String MP_SERVER_AUTHORIZE_USERNAME = "username";
	public static final String MP_SERVER_AUTHORIZE_ACTION = "action";
	public static final String MP_SERVER_AUTHORIZE_CLAIMS = "claims";
	
	public static final String MP_SERVER_AUTHORIZE_ACTION_OK = "ok";

	
}
