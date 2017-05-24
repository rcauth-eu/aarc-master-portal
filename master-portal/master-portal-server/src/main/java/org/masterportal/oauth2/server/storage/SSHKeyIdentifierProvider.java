package org.masterportal.oauth2.server.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;

public class SSHKeyIdentifierProvider extends IdentifierProvider {

    public SSHKeyIdentifierProvider() {
	super("");
    }
	
    @Override
    public Identifier get() {
	return (Identifier) new SSHKeyIdentifier(null, null);
    }
	

	
}
