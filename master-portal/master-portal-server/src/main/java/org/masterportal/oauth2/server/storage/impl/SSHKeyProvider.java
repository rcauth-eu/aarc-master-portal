package org.masterportal.oauth2.server.storage.impl;

import org.masterportal.oauth2.server.storage.SSHKey;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;

import javax.inject.Provider;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 * Provider Class for {@link SSHKey} objects.
 */

public class SSHKeyProvider extends IdentifiableProviderImpl<SSHKey> {

    public SSHKeyProvider(Provider<Identifier> idProvider) {
	super(idProvider);
    }

    /**
     * @return new SSHKey object with a null identifier (since we don't really
     * use a single-value identifier.
     */
    @Override
    public SSHKey get(boolean createNewIdentifier) {
	return new SSHKey(null);
    }
}
