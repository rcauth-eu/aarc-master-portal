package org.masterportal.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;

public interface MPOA4MPConfigTags extends OA4MPConfigTags {

	// Name of table containing the SSH keys
	public static final String SSH_KEY_STORE = "sshKeys";
	
	// attribute of the myproxy tag
	public static final String MYPROXY_PASSWORD = "password";
	
	// inner child elements of the myproxy tag
	public static final String MYPROXY_DEFAULT_LIFETIME = "defaultLifetime";
	public static final String MYPROXY_MAXIMUM_LIFETIME = "maximumLifetime";
	
	// validators
	public static final String MYPROXY_REQ_VALIDATORS = "validators";
	public static final String MYPROXY_REQ_VALIDATOR = "validator";
	public static final String MYPROXY_REQ_VALIDATOR_HANDLER = "handler";
	public static final String MYPROXY_REQ_VALIDATOR_INPUT = "input";
	public static final String MYPROXY_REQ_VALIDATOR_INPUT_NAME = "name";
}
