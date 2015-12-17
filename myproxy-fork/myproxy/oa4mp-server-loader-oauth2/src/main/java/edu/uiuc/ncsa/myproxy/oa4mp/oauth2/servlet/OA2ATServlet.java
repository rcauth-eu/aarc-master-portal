package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAccessTokenServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.IssuerTransactionState;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTokenException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.server.*;
import org.apache.commons.codec.digest.DigestUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Map;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.CLIENT_SECRET;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/3/13 at  2:03 PM
 */
public class OA2ATServlet extends AbstractAccessTokenServlet {
    @Override
    public void preprocess(TransactionState state) throws Throwable {
        super.preprocess(state);
        state.getResponse().setHeader("Cache-Control", "no-store");
        state.getResponse().setHeader("Pragma", "no-cache");

        OA2ServiceTransaction st = (OA2ServiceTransaction) state.getTransaction();
        Map<String, String> p = state.getParameters();
        String givenRedirect = p.get(OA2Constants.REDIRECT_URI);

        //Spec says that the redirect must match one of the ones stored and if not, the request is rejected.
        OA2ClientCheck.check(st.getClient(), givenRedirect);
        // Store the callback the user needs to use for this request, since the spec allows for many.
        st.setCallback(URI.create(p.get(OA2Constants.REDIRECT_URI)));
        // If there is a nonce in the initial request, it must be returned as part of the access token
        // response to prevent replay attacks.
        // Here is where we put the information from the session for generating claims in the id_token
        if (st.getNonce() != null && 0 < st.getNonce().length()) {
            p.put(OA2Constants.NONCE, st.getNonce());
        }


        p.put(OA2Constants.CLIENT_ID, st.getClient().getIdentifierString());
        if (getServiceEnvironment().getServiceAddress() != null) {
            String x = getServiceEnvironment().getServiceAddress().toString();
            x = x.substring(0, x.lastIndexOf("/"));
            // This is to be the server only, without the path. In the service tag, the complete
            // address + path is given.
            p.put(OA2Claims.ISSUER, x);

        } else {
            throw new NFWException("Error: no service address was found in the configuration.");
        }
        p.put(OA2Claims.SUBJECT, st.getUsername());
        if (st.hasAuthTime()) {
            // convert the date to a time if needed.
            p.put(OA2Constants.AUTHORIZATION_TIME, Long.toString(st.getAuthTime().getTime() / 1000));
        }
    }


    /**
     * The lifetime of the refresh token. This is the non-zero minimum of the client's requested
     * lifetime, the user's request at authorization time and the server global limit.
     *
     * @param st2
     * @return
     */
    protected long computeRefreshLifetime(OA2ServiceTransaction st2) {
        OA2Client client = (OA2Client) st2.getClient();
        long lifetime = Math.max(st2.getRefreshTokenLifetime(), client.getRtLifetime());
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        if (oa2SE.getRefreshTokenLifetime() <= 0) {
            throw new NFWException("Internal error: the server-wide default for the refresh token lifetime has not been set.");
        }
        lifetime = Math.min(lifetime, oa2SE.getRefreshTokenLifetime());
        return lifetime;

    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        String grantType = getFirstParameterValue(request, OA2Constants.GRANT_TYPE);
        if (grantType == null) {
            warn("Error servicing request. No grant type was given. Rejecting request.");
            throw new GeneralException("Error: Could not service request");
        }
        OA2Client client = (OA2Client) getClient(request);
        checkClient(client);

        String rawSecret = getFirstParameterValue(request, CLIENT_SECRET);
        if (rawSecret == null) {
            throw new GeneralException("Error: No secret. request refused.");
        }
        if (!client.getSecret().equals(DigestUtils.shaHex(rawSecret))) {
            throw new GeneralException("Error: Secret is incorrect. request refused.");
        }


        if (grantType.equals(OA2Constants.REFRESH_TOKEN)) {
            doRefresh(request, response);
            return;
        }
        if (grantType.equals(OA2Constants.AUTHORIZATION_CODE_VALUE)) {
            IssuerTransactionState state = doDelegation(request, response);
            ATIResponse2 atResponse = (ATIResponse2) state.getIssuerResponse();

            OA2ServiceTransaction st2 = (OA2ServiceTransaction) state.getTransaction();
            if (client.isRTLifetimeEnabled() && ((OA2SE) getServiceEnvironment()).isRefreshTokenEnabled()) {
                RefreshToken rt = atResponse.getRefreshToken();
                st2.setRefreshToken(rt);
                rt.setExpiresIn(computeRefreshLifetime(st2));
                st2.setRefreshTokenValid(true);
            }
            getTransactionStore().save(st2);

            return;
        }
        warn("Error: grant type was not recognized. Request rejected.");
        throw new ServletException("Error: Unknown request type.");
    }


    protected OA2ServiceTransaction getByRT(RefreshToken refreshToken) throws IOException {
        if (refreshToken == null) {
            throw new GeneralException("Error: null refresh token encountered.");
        }
        RefreshTokenStore rts = (RefreshTokenStore) getTransactionStore();
        return rts.get(refreshToken);
    }

    protected OA2TokenForge getTF2() {
        return (OA2TokenForge) getServiceEnvironment().getTokenForge();
    }

    protected TransactionState doRefresh(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        RefreshToken oldRT = getTF2().getRefreshToken(request.getParameter(OA2Constants.REFRESH_TOKEN));
        OA2Client c = (OA2Client) getClient(request);
        checkClient(c);

        OA2ServiceTransaction t = getByRT(oldRT);
        if ((!((OA2SE) getServiceEnvironment()).isRefreshTokenEnabled()) || (!c.isRTLifetimeEnabled())) {
            throw new OA2RedirectableError(OA2Errors.REQUEST_NOT_SUPPORTED, "Refresh tokens are not supported on this server", request.getParameter(OA2Constants.STATE), t.getCallback());
        }

        if (t == null || !t.isRefreshTokenValid()) {
            throw new InvalidTokenException("Error: The refresh token is no longer valid");
        }
        t.setRefreshTokenValid(false); // this way if it fails at some point we know it is invalid.
        RTIRequest rtiRequest = new RTIRequest(request, c, t.getAccessToken());
        RTI2 rtIsuuer = new RTI2(getTF2(), getServiceEnvironment().getServiceAddress());
        RTIResponse rtiResponse = (RTIResponse) rtIsuuer.process(rtiRequest);
        RefreshToken rt = rtiResponse.getRefreshToken();
        rt.setExpiresIn(computeRefreshLifetime(t));
        t.setRefreshToken(rtiResponse.getRefreshToken());
        t.setRefreshTokenValid(true);
        getTransactionStore().save(t);
        rtiResponse.write(response);
        IssuerTransactionState state = new IssuerTransactionState(
                request,
                response,
                rtiResponse.getParameters(),
                t,
                rtiResponse);
        return state;
    }

    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        ATIResponse2 atResponse = (ATIResponse2) iResponse;

        TransactionStore transactionStore = getTransactionStore();
        BasicIdentifier basicIdentifier = new BasicIdentifier(atResponse.getParameters().get(OA2Constants.AUTHORIZATION_CODE));
        OA2ServiceTransaction transaction = (OA2ServiceTransaction) transactionStore.get(basicIdentifier);
        if (transaction == null) {
            // Then this request does not correspond to an previous one and must be rejected asap.
            throw new OA2RedirectableError(OA2Errors.ACCESS_DENIED,
                    "No pending transaction found",
                    atResponse.getParameters().get(OA2Constants.STATE),
                    atResponse.getParameters().get(OA2Constants.REDIRECT_URI));
        }
        if (!transaction.isAuthGrantValid()) {
            String msg = "Error: Attempt to use invalid authorization code.  Request rejected.";
            warn(msg);
            throw new GeneralException(msg);
        }

        URI uri = URI.create(atResponse.getParameters().get(OA2Constants.REDIRECT_URI));
        if (!transaction.getCallback().equals(uri)) {
            String msg = "Error: Attempt to use alternate redirect uri rejected.";
            warn(msg);
            throw new GeneralException(msg);

        }
        /* Now we have to determine which scopes to return
           The spec says we don't have to return anything if the requested scopes are the same as the
           supported scopes. Otherwise, return what scopes *are* supported.
         */
        ArrayList<String> targetScopes = new ArrayList<>();
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();

        boolean returnScopes = false; // set true if something is requested we don't support
        for (String s : transaction.getScopes()) {
            if (oa2SE.getScopes().contains(s)) {
                targetScopes.add(s);
            } else {
                returnScopes = true;
            }
        }
        if (returnScopes) {
            atResponse.setSupportedScopes(targetScopes);
        }
        atResponse.setScopeHandler(oa2SE.getScopeHandler()); // so the same scopes in user info are returned here.
        atResponse.setServiceTransaction(transaction);
        // Need to do some checking but for now, just return transaction
        //return null;
        return transaction;
    }
}
