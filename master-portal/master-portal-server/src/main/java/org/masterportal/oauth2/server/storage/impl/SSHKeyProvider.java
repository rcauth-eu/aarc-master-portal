package org.masterportal.oauth2.server.storage.impl;

import javax.inject.Provider;

import org.masterportal.oauth2.server.storage.SSHKey;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;

public class SSHKeyProvider extends IdentifiableProviderImpl<SSHKey> {

    public SSHKeyProvider(Provider<Identifier> idProvider) {
	super(idProvider);
    }

    @Override
    public SSHKey get(boolean createNewIdentifier) {
	return new SSHKey(null);
    }
	
}
