package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys.TOKEN_KEY;
import static edu.uiuc.ncsa.security.core.util.DateUtils.checkTimestamp;

/**
 * For deployment in cases that there is a wholly external authorization webapp.
 * That webapp makes a call to this servlet following a specific mini-protocol
 * and the response from this servlet contains the redirect url which must then
 * cause a redirect in the user's browser.
 * <p>Created by Jeff Gaynor<blifetr>
 * on 2/13/14 at  3:24 PM
 */
public abstract class AuthorizedServlet extends CRServlet {
    public static final String AUTHORIZATION_USER_NAME_KEY = "userName";
    public static final String AUTHORIZATION_PASSWORD_KEY = "password";
    public static final String AUTHORIZATION_CERT_LIFETIME_KEY = "lifetime";
    public static final String STATUS_KEY = "status";
    public static final String STATUS_OK = "ok";
    public static final String REDIRECT_URL_KEY = "redirect_url";

    public abstract String createCallback(ServiceTransaction transaction);

    public static class ProtocolParameters {
        public String token;
        public String loa;
        public String userId;
        public long lifetime;
        public String password;
    }

    /**
     * This will take the HTTP request and parse it into parameters. This method is the one to override
     * if you have tweaks to the basic protocol.
     *
     * @param request
     * @return
     */
    protected ProtocolParameters parseRequest(HttpServletRequest request) throws ServletException {
        ProtocolParameters p = new ProtocolParameters();
        String ag = request.getParameter(CONST(TOKEN_KEY));
        ServiceTransaction trans = null;
        say("starting request for token =" + ag);
        if (ag == null) {
            throw new GeneralException("Error: Invalid request -- no token. Request rejected.");
        }
        p.userId = request.getParameter(AUTHORIZATION_USER_NAME_KEY);
        p.password = request.getParameter(AUTHORIZATION_PASSWORD_KEY);
        String xUsername = getServiceEnvironment().getUsernameTransformer().createMyProxyUsername(request);
        if (xUsername != null) {
            p.userId = xUsername;
        }

        String lifetimeS = request.getParameter(AUTHORIZATION_CERT_LIFETIME_KEY);
        p.lifetime = trans.getLifetime();
        if (lifetimeS != null && 0 < lifetimeS.length()) {
            try {
                p.lifetime = Long.parseLong(lifetimeS);
            } catch (Throwable t) {
                // do nothing
            }
        }

        return p;
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        /**
         * For the case that this is being used strictly as a back channel for authorized users.
         * This will process the request and return a standard response that includes the redirect
         * url. Applications calling this must parse the response and use it as per the spec.,  sending
         * it as a redirect to the user's browser.
         * @param request
         * @param response
         * @throws Throwable
         */
        ProtocolParameters p = parseRequest(request);
        ServiceTransaction trans = getAndCheckTransaction(p);
        trans.setUsername(p.userId);
        getTransactionStore().save(trans); // keep the user name
        createMPConnection(trans.getIdentifier(), p.userId, p.password, p.lifetime);
        doRealCertRequest(trans, "");
        writeResponse(response, trans);
    }

    /**
     * Write the response to the output stream and returns the callback that was generated, if there is one.
     * @param response
     * @param transaction
     * @return
     * @throws IOException
     */
    protected void writeResponse(HttpServletResponse response, ServiceTransaction transaction) throws IOException {
        String cb = createCallback(transaction);

        Writer w = response.getWriter();
        String returnedString = STATUS_KEY + "=" + STATUS_OK + "\n";
        response.setStatus(HttpStatus.SC_OK);
        returnedString = returnedString + REDIRECT_URL_KEY + "=" + cb;
        w.write(returnedString);
        w.close();
        response.sendRedirect(cb);
    }

    /*
   Get the transaction associated with the authorization grant token and check that it passes sanity
   checks. If so, return it, If not, throw the appropriate exception.
*/
    protected ServiceTransaction getAndCheckTransaction(ProtocolParameters p) throws Throwable {
        String token = p.token;
        say("checking timestamp");
        DateUtils.checkTimestamp(token);
        AuthorizationGrant grant = MyProxyDelegationServlet.getServiceEnvironment().getTokenForge().getAuthorizationGrant(token);
        checkTimestamp(grant.getToken());
        ServiceTransaction trans = MyProxyDelegationServlet.getServiceEnvironment().getTransactionStore().get(grant);
        say("retrieving transaction (Y/n)=" + (trans != null));
        if (trans == null) {
            warn("Error: no delegation request found for " + token);
            throw new GeneralException("Error: no delegation request found.");
        }
        say("checking client");
        checkClient(trans.getClient());
        say("client ok");
        return trans;
    }

}
