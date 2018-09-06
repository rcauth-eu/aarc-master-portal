package org.masterportal.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;

public interface MPOA4MPConfigTags extends OA4MPConfigTags {
    // the name of the ssh keys store backend
    public static final String SSH_KEY_STORE = "sshKeys";
    // name of the ssh keys node
    public static final String SSH_KEYS = "sshkeys";
    // name of max ssh keys childnode
    public static final String MAX_SSH_KEYS = "max";

    // whether the autoregister endpoint is enabled
    public static final String AUTOREGISTER_ENDPOINT_ENABLED = "enableAutoRegisterEndpoint";
    
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
