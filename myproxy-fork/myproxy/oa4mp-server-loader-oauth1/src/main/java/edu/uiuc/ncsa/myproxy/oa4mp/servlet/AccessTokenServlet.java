package edu.uiuc.ncsa.myproxy.oa4mp.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAccessTokenServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.TransactionNotFoundException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.ATResponse;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.token.Verifier;

import java.io.IOException;

import static edu.uiuc.ncsa.security.core.util.DateUtils.checkTimestamp;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 18, 2011 at  11:20:06 AM
 */
public class AccessTokenServlet extends AbstractAccessTokenServlet {
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        ATResponse atResponse = (ATResponse)  iResponse;
        Verifier verifier = atResponse.getVerifier();
        debug("5.a. verifier = " +  atResponse.getVerifier());
        checkTimestamp(verifier.getToken());
        ServiceTransaction transaction = (ServiceTransaction) getTransactionStore().get(verifier);
        if(transaction == null){
            throw new TransactionNotFoundException("No transaction found for verifier " + verifier);
        }
        checkClient(transaction.getClient());
        String cc = "client=" + transaction.getClient().getIdentifierString();
        info("5.a. " + cc);

        debug("5.a. grant valid=" + transaction.isAuthGrantValid() + ", at valid=" + transaction.isAccessTokenValid());
        if (!transaction.isAuthGrantValid() || transaction.isAccessTokenValid()) {
            String msg = "Error: the state of the transaction is invalid for auth grant " + transaction.getAuthorizationGrant();
            warn(msg);
            throw new GeneralException(msg);
        }
        return transaction;
    }
}
