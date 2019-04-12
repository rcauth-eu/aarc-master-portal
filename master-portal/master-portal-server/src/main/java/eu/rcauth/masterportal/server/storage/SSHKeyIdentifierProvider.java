package eu.rcauth.masterportal.server.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 * Note: we don't really use an Identifier for the SSH Keys, since they are
 * identified by the unique combination of user and label, and the upstream
 * Identifier class is not really suitable for that.
 */
public class SSHKeyIdentifierProvider<V extends Identifier> extends IdentifierProvider<Identifier> {

    public SSHKeyIdentifierProvider() {
        super("");
    }
	
    @Override
    public SSHKeyIdentifier get() {
        return new SSHKeyIdentifier(null, null);
    }


}
