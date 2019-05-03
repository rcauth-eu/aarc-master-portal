package eu.rcauth.masterportal.server.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizationServer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;
import edu.uiuc.ncsa.security.servlet.PresentableState;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import net.sf.json.JSONObject;

import eu.rcauth.masterportal.MPClientContext;
import eu.rcauth.masterportal.MPServerContext;
import eu.rcauth.masterportal.server.MPOA2RequestForwarder;
import eu.rcauth.masterportal.server.MPOA2ServiceTransaction;
import eu.rcauth.masterportal.servlet.util.CookieAwareHttpServletResponse;
import eu.rcauth.masterportal.servlet.util.UpdateParameterHttpServletRequest;

/*
 * Custom build Authorization Server for Master Portal
 *
 * Instead of authenticating the user here, it forwards the AuthN
 * request to the Delegation Server by initiating another OAuth2
 * flow between the Master Portal and Delegation Server
 *
 * <p>Created by Tamas Balogh</p>
 */
public class MPOA2AuthorizationServer extends OA2AuthorizationServer {

    /* NOTE: ensures that the transaction which is being used is a
     * MPOA2ServiceTransaction instance instead of a OA2ServiceTransaction.
     * Hence MPOA2AuthorizedServletUtil only overrides createNewTransaction().
     * We need MPOA2ServiceTransaction to handle keeping state between the
     * mp-client and mp-server via the MPClientSessionIdentifier.
     */
    @Override
    protected MPOA2AuthorizedServletUtil getInitUtil() {
        return new MPOA2AuthorizedServletUtil(this);
    }

    /*
     * This method is called at the end of the original AuthN flow which
     * displays an jsp expecting a username and password. Here we override this
     * with a simple forward to the /startRequest endpoint in case of a new
     * authN request.
     */
    @Override
    public void present(PresentableState state) throws Throwable {
        AuthorizedState aState = (AuthorizedState) state;
        HttpServletRequest request = aState.getRequest();
        HttpServletResponse response = aState.getResponse();
        OA2ServiceTransaction transaction = (OA2ServiceTransaction)(aState.getTransaction());
        postprocess(new TransactionState(request, response, null, transaction));

        switch (aState.getState()) {
            case AUTHORIZATION_ACTION_START:
                // Check we have a state parameter, or we cannot keep track of
                // the redirect to the client part
                String stateParam=getParam(request, "state");
                if (stateParam == null || stateParam.isEmpty()) {
                    error("Error: request does not contain required (non-empty) state parameter");
                    String redirect_uri = request.getParameter(OA2Constants.REDIRECT_URI);
                    if (redirect_uri == null || redirect_uri.isEmpty() ) {
                        throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST, "Need non-empty state parameter in request", "");
                    } else {
                        debug("Using "+OA2Constants.REDIRECT_URI+" = "+redirect_uri);
                        throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST, "Need non-empty state parameter in request", "", redirect_uri);
                    }
                }

                // wrap the request object so that we can replace a request parameter
                UpdateParameterHttpServletRequest newRequest = new UpdateParameterHttpServletRequest(request);

                // create String with the effective scopes for the client
                Collection<String> scopes = transaction.getScopes();
                String scopesString=String.join(" ", scopes.toArray(new String[0]));
                newRequest.setParam(OA2Constants.SCOPE, scopesString);

                info("Forwarding authorization request to MP-Client (/startRequest)");

                // wrap the response object so that we can look at the cookies going to the browser
                CookieAwareHttpServletResponse newResponse = new CookieAwareHttpServletResponse(response);

                // forward request
                ServletContext serverContext = getServletConfig().getServletContext();
                ServletContext clientContext = serverContext.getContext(MPClientContext.MP_CLIENT_CONTEXT);

                try {
                    RequestDispatcher dispatcher = clientContext.getRequestDispatcher(MPClientContext.MP_CLIENT_START_ENDPOINT);
                    MPOA2RequestForwarder.forwardRequest(newRequest, newResponse, dispatcher, false);
                    //dispatcher.forward(state.getRequest(), response);
                } catch (Throwable t) {
                    if (t instanceof GeneralException) {
                        throw t;
                    } else {
                        throw new GeneralException("Failed to redirect authentication request to MasterPortal Client!",t);
                    }
                }

                info("Done with authorization request forwarding");

                // extract the cookie containing the clientID
                // this cookie is then saved into the transaction store so that we can tie the MP-Client session to
                // the MP-Server session in upcoming requests.
                String clientID = newResponse.getCookie(MPClientContext.MP_CLIENT_REQUEST_ID);
                MPOA2ServiceTransaction trans = (MPOA2ServiceTransaction)aState.getTransaction();
                trans.setMPClientSessionIdentifier(clientID);
                // getTransactionStore() returns non-generic
                @SuppressWarnings("unchecked")
                TransactionStore<MPOA2ServiceTransaction> store = getTransactionStore();
                store.save( trans );

                break;

            case AUTHORIZATION_ACTION_OK:
                break;

            default:
                // fall through and do nothing
                debug("Hit default case in MPOA2AuthorizationServer2 servlet");
        }
    }

    /*
     * This method inserts the authenticated username into the transaction store, once the AuthN returned with
     * success.
     */
    @Override
    public void prepare(PresentableState state) throws Throwable {
        super.prepare(state);

        if (state.getState() == AUTHORIZATION_ACTION_OK) {

            MPOA2ServiceTransaction trans =  (MPOA2ServiceTransaction) ((AuthorizedState)state).getTransaction();

            // get authorized username and save it into the transaction

            String username = (String) state.getRequest().getAttribute(MPServerContext.MP_SERVER_AUTHORIZE_USERNAME);

            if (username == null)
                throw new GeneralException("Username was not found in authentication reply!");

            trans.setUsername(username);

            // get claims issued by the delegation server and save it into the transaction

            String jsonClaims = (String) state.getRequest().getAttribute(MPServerContext.MP_SERVER_AUTHORIZE_CLAIMS);
            debug("retrieved claims: "+jsonClaims);

            if (jsonClaims == null)
                warn("No claims returned by the Delegation Server! Check if the right SCOPES are sent by the Master Portal!");

            // Now we can set the new claims
            // NOTE: iss and aud are set in createRedirect() via claimsUtil.processAuthorizationClaims()
            trans.setClaims( JSONObject.fromObject(jsonClaims) );
        }
    }

    /*
     * Creates a redirect to the VO-Portal's /ready servlet, sending him the code & state
     */
    @Override
    protected void createRedirect(HttpServletRequest request, HttpServletResponse response, ServiceTransaction trans) throws Throwable {
        // NOTE: We cannot call super.createRedirect() since the we need to skip
        // a few parts. Hence we override.
        String rawrtl = request.getParameter(AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY);
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) trans;
        try {
            if (rawrtl != null && !rawrtl.isEmpty())
                st2.setRefreshTokenLifetime(Long.parseLong(rawrtl) * 1000);
        } catch (Throwable t) {
            st2.setRefreshTokenLifetime(0L);
        }

        info("3.b. transaction has user name = " + trans.getUsername());
        // The right place to invoke the pre-processor.
        preprocess(new TransactionState(request, response, null, trans));
        String statusString = " transaction =" + trans.getIdentifierString() + " and client=" + trans.getClient().getIdentifierString();
        trans.setVerifier(MyProxyDelegationServlet.getServiceEnvironment().getTokenForge().getVerifier());
        MyProxyDelegationServlet.getServiceEnvironment().getTransactionStore().save(trans);

        debug("4.a. verifier = " + trans.getVerifier() + ", " + statusString);

        OA2ClaimsUtil claimsUtil = new OA2ClaimsUtil((OA2SE) getServiceEnvironment(), st2);
        claimsUtil.processAuthorizationClaims(request, (OA2ServiceTransaction) trans);

        // At this point, all authentication has been done, everything is set up and the next stop in the flow is the
        // redirect back to the client.
        Map<String,String> reqParamMap = new HashMap<>();
        reqParamMap.put(OA2Constants.STATE, (String) request.getAttribute(OA2Constants.STATE));

        String cb = createCallback(trans, reqParamMap);
        info("4.a. starting redirect to " + cb + ", " + statusString);
        response.sendRedirect(cb);
        info("4.b. Redirect to callback " + cb + " ok, " + statusString);

    }

    /*
     * Exchange the order in which parameters are extracted from the request. This method prefers the
     * ATTRIBUTEs over the PARAMETERs. This is needed for this implementation because the code&state
     * used to keep the session are sent as ATTRIBUTEs (PARAMETERs are immutable inside a request)
     */
    @Override
    protected String getParam(HttpServletRequest request, String key) {
        Object oo = request.getAttribute(key);
        if (oo != null) {
            String x = oo.toString();
            if ( ! x.isEmpty() )
                return x;
        }

        // Note that this might return null or an empty String
        return request.getParameter(key);
    }

    /*
     * Extract the action parameter using the getParam preferring ATTRIBUTEs over PARAMETERs.
     */
    @Override
    public int getState(HttpServletRequest request) {
        String action = getParam(request, AUTHORIZATION_ACTION_KEY);
        info("servlet /"+this.getServletName()+" : action = " + action);
        if (action == null || action.length() == 0)
            return AUTHORIZATION_ACTION_START;
        if (action.equals(AUTHORIZATION_ACTION_OK_VALUE))
            return AUTHORIZATION_ACTION_OK;

        throw new GeneralException("Error: unknown authorization request action = \"" + action + "\"");
    }

}

