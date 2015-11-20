package org.masterportal.oauth2.server.servlet;


import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAuthorizationServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.servlet.PresentableState;
import net.sf.json.JSONObject;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys.TOKEN_KEY;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/7/14 at  11:44 AM
 */
public class OA2AuthorizationServer2 extends AbstractAuthorizationServlet {
    @Override
    protected AccessToken getAccessToken(HttpServletRequest request) {
        throw new NotImplementedException("No access token is available");
    }

    public String AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY = "AuthRTL";
    public String AUTHORIZED_ENDPOINT = "/authorized";
    public String AUTHORIZATION_REFRESH_TOKEN_LIFETIME_VALUE = "rtLifetime";

    /**
     * This class is needed to pass information between servlets, where one servlet
     * calls another.
     */
    static class MyHttpServletResponseWrapper
            extends HttpServletResponseWrapper {

        private StringWriter sw = new StringWriter();

        public MyHttpServletResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        int internalStatus = 0;

        @Override
        public void setStatus(int sc) {
            internalStatus = sc;
            super.setStatus(sc);
            if (!(200 <= sc && sc < 300)) {
                setExceptionEncountered(true);
            }
        }

        public int getStatus() {
            return internalStatus;
        }

        public PrintWriter getWriter() throws IOException {
            return new PrintWriter(sw);
        }

        public ServletOutputStream getOutputStream() throws IOException {
            throw new UnsupportedOperationException();
        }

        public String toString() {
            return sw.toString();
        }

        /**
         * If in the course of processing an exception is encountered, set this to be true. This class
         * is made to be passed between servlets and the results harvested, but if one of the servlets encounters
         * an exception, that is handled with a redirect (in OAuth 2) so nothing ever gets propagated back up the
         * stack to show that. This should be checked to ensure that did not happen.
         *
         * @return
         */
        boolean isExceptionEncountered() {
            return exceptionEncountered;
        }

        void setExceptionEncountered(boolean exceptionEncountered) {
            this.exceptionEncountered = exceptionEncountered;
        }

        boolean exceptionEncountered = false;
    }


    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        Map<String, String> map = getFirstParameters(request);

        info("printing all request parameters during thread : " + Thread.currentThread().getId());
        printAllParameters(request);

        if (map.containsKey(OA2Constants.RESPONSE_TYPE)) {

        	info(" AUTHORIZATION START ");
        	
        	info("Calling /authorized to get code & state.");
        	
            // Probably means this is an initial request. Pass it along to the init servlet to
            // unscramble it.
            MyHttpServletResponseWrapper wrapper = new MyHttpServletResponseWrapper(response);
                        
            JSPUtil.fwd(request, wrapper, AUTHORIZED_ENDPOINT);

            if (wrapper.isExceptionEncountered()) {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, wrapper.toString(), wrapper.getStatus());
            } // something happened someplace else and the exception was handled.
            String content = wrapper.toString();
            // issue now is that the nonce was registered in the init servlet (as it should be for OA1)
            // and now it will be rejected ever more.
            JSONObject j = JSONObject.fromObject(content);
            String code = j.get("code").toString();
            String state = j.get("state").toString();
            request.setAttribute("code", code);
            request.setAttribute("state", state);
            
            info("The /authorized endpoint returned with code & state");

            info("Forwarding authorization request to master-portal-client (/startRequest)");
           
            ServletContext serverContext = getServletConfig().getServletContext();
            ServletContext clientContext = serverContext.getContext("/mp-oa2-client");
             
            RequestDispatcher dispatcher = clientContext.getRequestDispatcher("/startRequest");
            dispatcher.forward(request, response);
            
        } else {
        	
        	info(" AUTHORIZATION OK ");
        	
        	info("TOKE_KEY: " + TOKEN_KEY);
        	info("CONST of TOKEN_KEY: " + CONST(TOKEN_KEY));
        	info("TOKEN_KEY VALUE: " + getParam(request, CONST(TOKEN_KEY)));
        	
        	super.doIt(request, response);
        	
        }
        
        
        //super.doIt(request, response);
        
    }
    
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
    
    
    @Override
    public int getState(HttpServletRequest request) {
        String action = getParam(request, AUTHORIZATION_ACTION_KEY);
        log("action = " + action);
        if (action == null || action.length() == 0) return AUTHORIZATION_ACTION_START;
        if (action.equals(AUTHORIZATION_ACTION_OK_VALUE)) return AUTHORIZATION_ACTION_OK;
        throw new GeneralException("Error: unknown authorization request action = \"" + action + "\"");
    }

    
    @Override
    public void prepare(PresentableState state) throws Throwable {
        super.prepare(state);
        if (state.getState() == AUTHORIZATION_ACTION_START) {
            state.getRequest().setAttribute(AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY, AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY);
        }
        if (state.getState() == AUTHORIZATION_ACTION_OK) {
            AuthorizedState authorizedState = (AuthorizedState) state;
            ((OA2ServiceTransaction) authorizedState.getTransaction()).setAuthTime(new Date());

            String username = (String) state.getRequest().getAttribute("username");
            ((AuthorizedState)state).getTransaction().setUsername(username);
            
        }
    }


    @Override
    public void present(PresentableState state) throws Throwable {
        super.present(state);

    }

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
        //super.createRedirect(request, response, trans);

        info("3.b. transaction has user name = " + trans.getUsername());
        // The right place to invoke the pre-processor.
        preprocess(new TransactionState(request, response, null, trans));
        String statusString = " transaction =" + trans.getIdentifierString() + " and client=" + trans.getClient().getIdentifierString();
        trans.setVerifier(MyProxyDelegationServlet.getServiceEnvironment().getTokenForge().getVerifier());
        MyProxyDelegationServlet.getServiceEnvironment().getTransactionStore().save(trans);

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

    @Override
    public String createCallback(ServiceTransaction trans, Map<String, String> params) {

        String cb = trans.getCallback().toString();
        String idStr = trans.getIdentifierString();
        try {
            cb = cb + (cb.indexOf("?") == -1 ? "?" : "&") + OA2Constants.AUTHORIZATION_CODE + "=" + URLEncoder.encode(idStr, "UTF-8");
            if (params.containsKey(OA2Constants.STATE)) {
                cb = cb + "&" + OA2Constants.STATE + "=" + URLEncoder.encode(params.get(OA2Constants.STATE), "UTF-8");
            }

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return cb;
    }

    /**
     * Spec says we do the cert request in the authorization servlet.
     *
     * @param trans
     * @param statusString
     * @throws Throwable
     */
    @Override
    protected void doRealCertRequest(ServiceTransaction trans, String statusString) throws Throwable {
        // do nix here in this protocol.
    }
}

