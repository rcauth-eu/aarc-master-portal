package eu.rcauth.masterportal.server.storage;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 * Provides the table column keys for the different columns
 */
public class SSHKeyKeys extends SerializationKeys {

    public SSHKeyKeys() {
	// the field declared as 'identifier' will be treated as a Primary Key
//	identifier(serial);
    }

    /** column key of label column */
    String label = "label";
    /** column key of userName column */
    String userName = "username";
    /** column key of pubKey column */
    String pubKey = "pub_key";
    /** column key of description column */
    String description = "description";
    /** column key of importTime column */
    String importTime = "import_time";

    /** return column key for label column */
    public String label(String... x) {
        if (0 < x.length) label = x[0];
        return label;
    }
    
    /** return column key for userName column */
    public String userName(String... x) {
        if (0 < x.length) userName = x[0];
        return userName;
    }
    
    /** return column key for pubKey column */
    public String pubKey(String... x) {
        if (0 < x.length) pubKey = x[0];
        return pubKey;
    }	
    
    /** return column key for description column */
    public String description(String... x) {
        if (0 < x.length) description = x[0];
        return description;
    }	
    
    /** return column key for importTime column */
    public String importTime(String... x) {
        if (0 < x.length) importTime = x[0];
        return importTime;
    }	
}
