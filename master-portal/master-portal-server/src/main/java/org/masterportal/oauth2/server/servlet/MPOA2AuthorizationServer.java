package org.masterportal.oauth2.server.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizationServer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;
import edu.uiuc.ncsa.security.servlet.PresentableState;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.masterportal.oauth2.MPClientContext;
import org.masterportal.oauth2.MPServerContext;
import org.masterportal.oauth2.server.MPOA2RequestForwarder;
import org.masterportal.oauth2.server.MPOA2ServiceTransaction;
import org.masterportal.oauth2.server.util.JSONConverter;
import org.masterportal.oauth2.servlet.util.CookieAwareHttpServletResponse;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

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
	
	/*
	@Override
	protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
		try {
			super.doIt(request, response);
		} catch (Throwable t) {
			
			System.out.println( t.getMessage() );			
			t.printStackTrace();
			
			//  The authorize endpoint handles exceptions differently, because it's called from the
			//  browser directly (through a redirect)
			 
			String redirect_uri = request.getParameter(OA2Constants.REDIRECT_URI);
			String code  = (String) request.getAttribute(OA2Constants.AUTHORIZATION_CODE);

			if ( redirect_uri == null && code != null ) {

				AuthorizationGrant grant = MyProxyDelegationServlet.getServiceEnvironment().getTokenForge().getAuthorizationGrant(code);
		        ServiceTransaction trans = MyProxyDelegationServlet.getServiceEnvironment().getTransactionStore().get(grant);	
				
		        redirect_uri = trans.getCallback().toString();
			}
			
			if ( redirect_uri != null ) {

				 //In case we find a redirect uri, try to forward the error to the VO Portal
				 

				if ( t instanceof OA2GeneralError ) {
					throw new OA2RedirectableError(OA2Errors.SERVER_ERROR,((OA2GeneralError)t).getDescription(),
							                       new String("" + ((OA2GeneralError)t).getHttpStatus()),redirect_uri);
				} else if ( t instanceof OA2RedirectableError ) {
					throw t;
				} else {
					throw new OA2RedirectableError(OA2Errors.SERVER_ERROR,t.getMessage(),"",redirect_uri);
				}
				
			} else if ( code != null ) {
			
		        
			} else {
					
				 // Forward caught error massages to a local error servlet endpoint which
				 // will then take care of displaying them. This is handled locally for the
				 // \/authorize endpoint because this endpoint is called from the browser directly

				StringBuffer buffer = new StringBuffer();
				buffer.append(MPServerContext.MP_SERVER_CONTEXT + "/error?");
				
				String clientID = request.getParameter(OA2Constants.CLIENT_ID);
				if (  clientID != null ) {
					buffer.append("identifier="+ clientID +"&");
				}
				
				buffer.append("cause="+ t.getClass().getSimpleName()  +"&");				
				
				buffer.append("message="+ t.getMessage() +"&");			
				
				StringWriter errors = new StringWriter();
				t.printStackTrace(new PrintWriter(errors));
				buffer.append("stackTrace="+errors.toString());
				
				response.sendRedirect(buffer.toString());
			}
		}
	}
	*/
	
	/*
	@Override
	protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
		try {
			super.doIt(request, response);
		} catch(Throwable t) {
			
			request.setAttribute("exception", t);
			RequestDispatcher dispatcher = getServletConfig().getServletContext().getRequestDispatcher(MPServerContext.MP_SERVER_CONTEXT + "/error");
			MPOA2RequestForwarder.forwardRequest(request, response, dispatcher, false);
			
		}
	}
	*/
	
	/*
	 * This method is called at the end of the original AuthN flow which displays an jsp expecting a username and 
	 * password. Here we override this with a simple forward to the /startRequest endpoint in case of a new authN request.
	 */
    @Override
    public void present(PresentableState state) throws Throwable {
    	AuthorizedState aState = (AuthorizedState) state;
    	postprocess(new TransactionState(state.getRequest(), aState.getResponse(), null, aState.getTransaction()));
    	
    	switch (aState.getState()) {
    		case AUTHORIZATION_ACTION_START:
        	
    			info("Forwarding authorization request to MP-Client (/startRequest)");
    			    			
    			// wrap the response object so that we can look at the cookies going to the browser
    			CookieAwareHttpServletResponse response = new CookieAwareHttpServletResponse(state.getResponse());
    			
    			// forward request
    			ServletContext serverContext = getServletConfig().getServletContext();
    			ServletContext clientContext = serverContext.getContext(MPClientContext.MP_CLIENT_CONTEXT);
             
    			try { 
    				RequestDispatcher dispatcher = clientContext.getRequestDispatcher(MPClientContext.MP_CLIENT_START_ENDPOINT);
    				MPOA2RequestForwarder.forwardRequest(state.getRequest(), response, dispatcher, false);
    				//dispatcher.forward(state.getRequest(), response);
    			} catch (Throwable t) {
    				if (t instanceof GeneralException) {
    					throw t;
    				} else {
    					throw new GeneralException("Faild to redirect authentication request to MasterPortal Client!",t);
    				}
    			}
        	
    			info("Done with authorization request forwarding");
    			
    			// extract the cookie containing the clientID 
    			// this cookie is then saved into the transaction store so that we can tie the MP-Client session to
    			// the MP-Server session in upcoming requests.
    			String clientID = response.getCookie(MPClientContext.MP_CLIENT_REQUEST_ID);
    			((MPOA2ServiceTransaction)aState.getTransaction()).setMPClientSessionIdentifier(clientID);
    			getTransactionStore().save( aState.getTransaction() );
    			
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
            
            if (username == null) {
            	throw new GeneralException("Username was not found in authentication reply!");
            }
            
            trans.setUsername(username);  
            
            // get claims issued by the delegation server and save it into the transaction
            
            String jsonClaims = (String) state.getRequest().getAttribute(MPServerContext.MP_SERVER_AUTHORIZE_CLAIMS);
            
            if (jsonClaims == null) {
            	warn("No claims returned by the Delegation Server! Check if the right SCOPES are sent by the Master Portal!");
            }
            
            trans.setClaims( (Map<String, Object>) JSONConverter.fromJSONObject(jsonClaims) );            
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
            if (rawrtl != null && !rawrtl.isEmpty()) {
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
            if ( ! x.isEmpty() ) {
            	return x;
            }
        }

        x = request.getParameter(key);
        if (x != null && ! x.isEmpty()) {
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

