package org.masterportal.oauth2.server.storage;

import java.net.URI;
import edu.uiuc.ncsa.security.core.Identifier;

public class SSHKeyIdentifier implements Identifier {

	String identifier = null;
	
	public SSHKeyIdentifier(String userName, String label) {
	    if (userName!=null && label!=null)	{
		this.identifier = userName + ":" + label;
	    }
	}
	
	@Override
	public int compareTo(Object o) {
	    if ( o instanceof SSHKeyIdentifier ) {
		return identifier.compareTo( ((SSHKeyIdentifier)o).identifier);
	    } else {
		return identifier.compareTo( o.toString() );
	    }
	}

	@Override
	public URI getUri() {
	    return null;
	}
	
	@Override
	public String toString() {
	    return identifier;
	}

	/* Override these two methods so that we can use this object as the
	 * key in a hash lookup table
	 */
	
	@Override
	public boolean equals(Object obj) {
	    return identifier.equals(obj.toString());
	}

	@Override
	public int hashCode() {
	    return identifier.hashCode();
	}
	
}
