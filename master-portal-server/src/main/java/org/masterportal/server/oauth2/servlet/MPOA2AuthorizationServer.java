package org.masterportal.server.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizationServer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.servlet.PresentableState;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/*
 * Custom build Authorization Server for Master Portal
 * 
 * Instead of authenticating the user here, it forwards the AuthN
 * request to the Delegation Server by initiating another OAuth2
 * flow between the Master Portal and Delegation Server
 */
public class MPOA2AuthorizationServer extends OA2AuthorizationServer {
    
	public static final String MP_CLIENT_CONTEXT = "/mp-oa2-client";
	public static final String MP_CLIENT_START_ENDPOINT = "/startRequest";
	
	/*
	 * This method is called at the end of the original AuthN flow which displays an jsp expecting a username and 
	 * password. Here we override this with a simple forward to the right endpoint in case of a new authN request.
	 */
    @Override
    public void present(PresentableState state) throws Throwable {
    	AuthorizedState aState = (AuthorizedState) state;
    	postprocess(new TransactionState(state.getRequest(), aState.getResponse(), null, aState.getTransaction()));
    	
    	switch (aState.getState()) {
    		case AUTHORIZATION_ACTION_START:
        	
    			info("Forwarding authorization request to master-portal-client (/startRequest)");
            
    			ServletContext serverContext = getServletConfig().getServletContext();
    			ServletContext clientContext = serverContext.getContext(MP_CLIENT_CONTEXT);
             
    			RequestDispatcher dispatcher = clientContext.getRequestDispatcher(MP_CLIENT_START_ENDPOINT);
    			dispatcher.forward(state.getRequest(), state.getResponse());
        	
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
            String username = (String) state.getRequest().getAttribute("username");
            ((AuthorizedState)state).getTransaction().setUsername(username);      
        }
    }

    /*
     * Creates a redirect to the VO-Portal's /ready servlet, sending him the code & state 
     */
    @Override
    protected void createRedirect(HttpServletRequest request, HttpServletResponse response, ServiceTransaction trans) throws Throwable {
        String rawrtl = request.getParameter(AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY);
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) trans;
        try {
            if (rawrtl != null) {
                st2.setRefreshTokenLifetime(Long.parseLong(rawrtl) * 1000);
            }
        } catch (Throwable t) {
            st2.setRefreshTokenLifetime(0L);
        }

        info("3.b. transaction has user name = " + trans.getUsername());
        // The right place to invoke the pre-processor.
        preprocess(new TransactionState(request, response, null, trans));
        String statusString = " transaction =" + trans.getIdentifierString() + " and client=" + trans.getClient().getIdentifierString();
        trans.setVerifier(MyProxyDelegationServlet.getServiceEnvironment().getTokenForge().getVerifier());
        MyProxyDelegationServlet.getServiceEnvironment().getTransactionStore().save(trans);

        // The original AuthN servlet initiates a test MyProxy connection here. I disabled this for now. 
        
        //createMPConnection(trans.getIdentifier(), trans.getUsername(), "", trans.getLifetime());
        // Change is to close this connection after verifying it works.
        //getMPConnection(trans.getIdentifier()).close();
        // Depending on the control flow, the next call may or may not require a connection to be re-opened.
        
        doRealCertRequest(trans, statusString);
        debug("4.a. verifier = " + trans.getVerifier() + ", " + statusString);
        
        Map<String,String> reqParamMap = new HashMap<String,String>();
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
        String x = null;
        
        Object oo = request.getAttribute(key);
        if (oo != null) {
            x = oo.toString();
            return x;
        }

        x = request.getParameter(key);
        if (x != null) {
        	return x;
        }
        
        return x;
    }
    
    /*
     * Extract the action parameter using the getParam preferring ATTRIBUTEs over PARAMETERs. 
     */
    @Override
    public int getState(HttpServletRequest request) {
        String action = getParam(request, AUTHORIZATION_ACTION_KEY);
        log("action = " + action);
        if (action == null || action.length() == 0) return AUTHORIZATION_ACTION_START;
        if (action.equals(AUTHORIZATION_ACTION_OK_VALUE)) return AUTHORIZATION_ACTION_OK;
        throw new GeneralException("Error: unknown authorization request action = \"" + action + "\"");
    }
    
}

