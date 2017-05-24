package org.masterportal.oauth2.server.storage;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

public class SSHKeyKeys extends SerializationKeys {

    public SSHKeyKeys() {
	// the field declared as 'identifier' will be treated as a Primary Key
//	identifier(serial);
    }
   
    String label = "label";
    String username = "username";
    String pub_key = "pub_key";
    String description = "description";
    String import_time = "import_time";
	
    public String label(String... x) {
        if (0 < x.length) label = x[0];
        return label;
    }
    
    public String username(String... x) {
        if (0 < x.length) username = x[0];
        return username;
    }
    
    public String pub_key(String... x) {
        if (0 < x.length) pub_key = x[0];
        return pub_key;
    }	
    
    public String description(String... x) {
        if (0 < x.length) description = x[0];
        return description;
    }	
    
    public String import_time(String... x) {
        if (0 < x.length) import_time = x[0];
        return import_time;
    }	
}
