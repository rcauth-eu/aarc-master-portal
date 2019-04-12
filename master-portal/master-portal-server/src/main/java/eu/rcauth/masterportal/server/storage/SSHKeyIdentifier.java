package eu.rcauth.masterportal.server.storage;

import java.net.URI;
import edu.uiuc.ncsa.security.core.Identifier;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 * Note: we don't really use an Identifier for the SSHKey class (the unique
 * combination of the two Strings, username and label is used a primary key).
 * This class is only used in order to be able to reuse the SQL implementation
 * of the Master Portal.
 */
public class SSHKeyIdentifier implements Identifier {

    String identifier = null;

	/**
	 * construct an identifier out of username and label, combining into
	 * single String with colon as separator
	 */
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

	/**
	 * SSH Key identifiers don't have a URI representation.
	 * @return null URI
	 */
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
		if (obj instanceof SSHKeyIdentifier )
            return identifier.equals(obj.toString());
		else
			return false;
	}

	@Override
	public int hashCode() {
	    return identifier.hashCode();
	}
}
