package eu.rcauth.masterportal.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;

public interface MPOA4MPConfigTags extends OA4MPConfigTags {
    // the name of the ssh keys store backend target
    public static final String SSH_KEY_STORE = "sshKeys";

    // name of the ssh keys API config node in the config file
    public static final String SSH_KEYS = "sshkeys";
    // name of max ssh keys attribute in the {@link #SSH_KEYS} node
    public static final String MAX_SSH_KEYS = "max";
    // name of required scope attribute in the {@link #SSH_KEYS} node
    public static final String SSH_KEYS_SCOPE = "scope";

    // attribute to define scope to be local, i.e. not to be forwarded to the DS
    public static final String SCOPE_LOCAL = "local";

    // whether the autoregister endpoint is enabled
    public static final String AUTOREGISTER_ENDPOINT_ENABLED = "enableAutoRegisterEndpoint";

    // attribute of the myproxy tag
    public static final String MYPROXY_PASSWORD = "password";

    // inner child elements of the myproxy tag
    public static final String MYPROXY_DEFAULT_LIFETIME = "defaultLifetime";
    // currently not being used
    public static final String MYPROXY_MAXIMUM_LIFETIME = "maximumLifetime";

    // validators
    public static final String MYPROXY_REQ_VALIDATORS = "validators";
    public static final String MYPROXY_REQ_VALIDATOR = "validator";
    public static final String MYPROXY_REQ_VALIDATOR_HANDLER = "handler";
    public static final String MYPROXY_REQ_VALIDATOR_INPUT = "input";
    public static final String MYPROXY_REQ_VALIDATOR_INPUT_NAME = "name";
}
