package org.masterportal.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;

public interface MPOA4MPConfigTags extends OA4MPConfigTags {

	
	// attribute of the myproxy tag
	public static final String MYPROXY_PASSWORD = "password";
	
	// inner child elements of the myproxy tag
	public static final String MYPROXY_DEFAULT_LIFETIME = "defaultLifetime";
	public static final String MYPROXY_MAXIMUM_LIFETIME = "maximumLifetime";
	
}
