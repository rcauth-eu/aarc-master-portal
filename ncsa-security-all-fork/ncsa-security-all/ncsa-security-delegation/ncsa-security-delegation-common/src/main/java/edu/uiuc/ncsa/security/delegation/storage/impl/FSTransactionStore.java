package edu.uiuc.ncsa.security.delegation.storage.impl;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.delegation.token.Verifier;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;
import java.io.IOException;


/**
 * Implementation of a transaction store backed by the file system.
 * <p>Created by Jeff Gaynor<br>
 * on Apr 28, 2010 at  3:01:10 PM
 */
public abstract class FSTransactionStore<V extends BasicTransaction> extends FileStore<V> implements TransactionStore<V> {
    protected FSTransactionStore(File storeDirectory,
                                 File indexDirectory,
                                 IdentifiableProvider<V> idp,
                                 TokenForge tokenForge,
                                 MapConverter<V> mp) {
        super(storeDirectory, indexDirectory, idp,  mp);
        this.tokenForge = tokenForge;
    }

    protected TokenForge tokenForge;
    public FSTransactionStore(File file,
                              IdentifiableProvider<V> idp, TokenForge tokenForge, MapConverter<V> mp) {
        super(file, idp, mp);
        this.tokenForge = tokenForge;
    }


    /**
     * Add code to store index references to the transaction by access token, verifier and
     * authorization grant.
     *
     * @param checkExists
     * @param t
     */
    @Override
    public void realSave(boolean checkExists, V t) {
        super.realSave(checkExists, t);
        try {
            if (t.hasAuthorizationGrant()) {
                createIndexEntry(t.getAuthorizationGrant().getToken(), t.getIdentifierString());
            }
            if (t.hasAccessToken()) {
                createIndexEntry(t.getAccessToken().getToken(), t.getIdentifierString());
            }
            if (t.hasVerifier()) {
                createIndexEntry(t.getVerifier().getToken(), t.getIdentifierString());
            }
        } catch (IOException e) {
            throw new GeneralException("Error serializing item " + t + "to file ");
        }
    }


    @Override
    public boolean delete(String identifier) {
        V t = (V) loadByIdentifier(identifier);
        boolean rc = super.delete(identifier);
        if (t.hasAuthorizationGrant()) {
            removeIndexEntry(t.getAuthorizationGrant().getToken());
        }
        if (t.hasAccessToken()) {
            removeIndexEntry(t.getAccessToken().getToken());
        }
        if (t.hasVerifier()) {
            removeIndexEntry(t.getVerifier().getToken());
        }
        return rc;
    }

    public V get(AuthorizationGrant authorizationGrant) {
        return getIndexEntry(authorizationGrant.getToken());
    }

    public V get(AccessToken accessToken) {
        return getIndexEntry(accessToken.getToken());
    }

    public V get(Verifier verifier) {
        return getIndexEntry(verifier.getToken());
    }

}
