package eu.rcauth.masterportal.client.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreUtil;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.servlet.ServiceClientHTTPException;

import java.util.Enumeration;
import java.util.HashMap;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;

import eu.rcauth.masterportal.MPClientContext;
import eu.rcauth.masterportal.MPServerContext;
import eu.rcauth.masterportal.client.MPOA2Asset;

/**
 * Simple /startRequest implementation that supports session keeping between the
 * MP Server and MP Client. It strips the 'code' and 'server' received as request
 * attributes and saves them for the purpose of session keeping on the MP Server.
 * In case any of the above mentioned attributes are missing the request will fail
 * since the originating MP Server session can no longer be identified by the
 * MP Client.
 * <p>
 * Afterwards, it continues to redirect to the service url of the configured
 * Delegation Server, just like a normal /startRequest would.
 *
 * @author "Tamás Balogh"
 *
 */
public class MPOA2ForwardingStartRequest extends ClientServlet {
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {

        info("1.a. Starting transaction");
        // Drumroll please: here is the work for this call.

        /* EXTRACT RELEVANT REQUEST PARAMETERS */

        HashMap<String,String> requestParameterMap = new HashMap<>();

        //printAllParameters(request);

        for ( Object key : request.getParameterMap().keySet() ) {
            String paramKey = (String) key;
            if ( ! isOA2Parameter(paramKey) )
                requestParameterMap.put( paramKey , request.getParameter(paramKey) );
        }

        // extract scope

        String MPServerRequestScopes = request.getParameter(OA2Constants.SCOPE);

        if ( MPServerRequestScopes == null || MPServerRequestScopes.isEmpty() ) {
            // fall back on regular scope and WARN
            warn("No SCOPE parameter found in the forwarded authorization request from the MP Server! Falling back on static SCOPE list");
        } else {
            requestParameterMap.put(OA2Constants.SCOPE, MPServerRequestScopes);
        }

        // create session Asset and Authorization Request

        Identifier id = AssetStoreUtil.createID();
        OA4MPResponse gtwResp = getOA4MPService().requestCert(id,requestParameterMap);

        // extract 'code' & 'state'

        // The MP-Server has to be able to identify its pending authentication session when
        // the MP-Client returns an authenticated username. For this reason, the code&state
        // pair set by MP-Server/authorized for the incoming /authorize request is sent and
        // saved at the beginning of the MP-Client session. The MPOA2ForwardingReadyServlet
        // will send the code&state pair together with the authenticated username back to
        // the MP-Server.

        String code = (String) request.getAttribute(MPServerContext.MP_SERVER_AUTHORIZE_CODE);
        String state = (String) request.getAttribute(MPServerContext.MP_SERVER_AUTHORIZE_STATE);

        if (code != null && !code.isEmpty() && state != null && !state.isEmpty()) {
            info("1.a. Saving code&state into asset store for later forwarding !");
            MPOA2Asset asset = (MPOA2Asset) getCE().getAssetStore().get(id);
            asset.setMPServerRequestCode(code);
            asset.setMPServerRequestState(state);

            getCE().getAssetStore().save(asset);
        } else {
            error("No code&state pair received! MP-Server will be unable to continue its pending auth request!");

            ServiceClientHTTPException e=new ServiceClientHTTPException("No code or state received! MP-Server will be unable to continue its pending auth request!");
            e.setStatus(HttpStatus.SC_BAD_REQUEST);
            throw e;
        }

        /* CONTINUE WITH REGULAR REDIRECT TO DELEGATION SERVER */

        // if there is a store, store something in it.
        Cookie cookie = new Cookie(MPClientContext.MP_CLIENT_REQUEST_ID, id.getUri().toString());
        cookie.setMaxAge(15 * 60); // 15 minutes
        cookie.setSecure(true);
        cookie.setPath("/");
        debug("id = " + id.getUri());
        response.addCookie(cookie);
        info("1.b. Got response. Creating page with redirect for " + gtwResp.getRedirect().getHost());

        response.setStatus(HttpStatus.SC_OK);
        response.sendRedirect(gtwResp.getRedirect().toString());
    }

    /**
     * Check if a parameter is an OpenID Connect specific Authorization Request
     * parameter or not.
     * @see <a href="https://docs.google.com/document/d/1cs3peO9FxA81KN-1RC6Z-auEFIwRbJpZ-SFuKbQzS50/pub#h.cfm05rlw4qy3">MyProxy OpenID Connect</a>
     *
     * @param key The parameter name to test
     * @return true if parameter is a standard OIDC Authorization parameter, false otherwise.
     */
    protected boolean isOA2Parameter(String key) {

        switch (key) {
            case OA2Constants.RESPONSE_TYPE:
            case OA2Constants.CLIENT_ID:
            case OA2Constants.SCOPE:
            case OA2Constants.REDIRECT_URI:
            case OA2Constants.STATE:
            case OA2Constants.NONCE:
            case OA2Constants.PROMPT:
            case OA2Constants.MAX_AGE:
            case OA2Constants.ID_TOKEN_HINT:
            case OA2Constants.REQUEST:
            case OA2Constants.REQUEST_URI:
                return true;
        }

        return false;
    }


    @Override
    protected void printAllParameters(HttpServletRequest request) {
        super.printAllParameters(request);

        System.out.println("> Attributes:");
        Enumeration attr = request.getAttributeNames();
        if (!attr.hasMoreElements()) {
            System.out.println(">  (none)");
        } else {
            while (attr.hasMoreElements()) {
                String name = attr.nextElement().toString();
                System.out.println(">  " + name);
                Object val = request.getAttribute(name);
                if (val != null)
                    System.out.println(">    " + request.getAttribute(name));
            }
        }

    }



}
