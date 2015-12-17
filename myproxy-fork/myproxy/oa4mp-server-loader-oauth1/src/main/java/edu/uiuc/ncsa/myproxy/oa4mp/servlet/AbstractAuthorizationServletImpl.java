package edu.uiuc.ncsa.myproxy.oa4mp.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAuthorizationServlet;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

import static net.oauth.OAuth.OAUTH_TOKEN;
import static net.oauth.OAuth.OAUTH_VERIFIER;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/7/14 at  11:44 AM
 */
public class AbstractAuthorizationServletImpl extends AbstractAuthorizationServlet {
    @Override
    protected AccessToken getAccessToken(HttpServletRequest request) {
        throw new NotImplementedException("No access token is used here");
    }

    @Override
    public String createCallback(ServiceTransaction trans, Map<String,String> params) {
        // FIXME!! Basic spec should return extra parameters it does not recognize?
        String cb = trans.getCallback().toString();
        return cb + (cb.indexOf("?") == -1 ? "?" : "&") + OAUTH_TOKEN + "=" + trans.getIdentifierString() + "&" + OAUTH_VERIFIER + "=" + trans.getVerifier().getToken();
    }

    /**
     * Spec says we do the cert request in the authorization servlet.
     * @param trans
     * @param statusString
     * @throws Throwable
     */
    @Override
    protected void doRealCertRequest(ServiceTransaction trans, String statusString) throws Throwable {
        doCertRequest(trans, statusString);
    }
}
