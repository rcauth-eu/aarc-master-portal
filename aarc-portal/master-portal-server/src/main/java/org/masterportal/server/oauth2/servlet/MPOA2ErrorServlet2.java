package org.masterportal.server.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import org.apache.commons.codec.binary.Base64;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;

/**
 * This servlet handles error redirects. If an error (such as a 404, 500 or anything else) occurs,
 * OAuth will intecept the response and throw an exception -- losing any other information.
 * Therefore, there must be a redirect and clients must be prepared to deal with these.
 * Generally there are a few error type pages
 * <p>Created by Jeff Gaynor<br>
 * on 9/4/12 at  6:03 PM
 */
public class MPOA2ErrorServlet2 extends MyProxyDelegationServlet {
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }

    public static final String MESSAGE = "message";
    public static final String IDENTIFIER = "identifier";
    public static final String STACK_TRACE = "stackTrace";
    public static final String CAUSE = "cause";

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        
    	Throwable t = (Throwable) request.getAttribute("exception");
    	
    	String redirect_uri = getParam(request, OA2Constants.REQUEST_URI);
    	String client_id = getParam(request, OA2Constants.CLIENT_ID);
    	
    	String cause = request.getParameter(CAUSE);
        String identifier = request.getParameter(IDENTIFIER);
        String stackTrace = request.getParameter(STACK_TRACE);
        
        request.setAttribute(CAUSE, cause);
        request.setAttribute(IDENTIFIER, identifier);
        request.setAttribute(MESSAGE, URLDecoder.decode(request.getParameter(MESSAGE), "UTF-8"));
        request.setAttribute(STACK_TRACE, stackTrace);

        if (identifier != null) {
        	Client client = getClient(BasicIdentifier.newID(identifier));
        	request.setAttribute("client", client);
        }
        
        JSPUtil.fwd(request, response, "/errorPage2.jsp");

    }
    
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
}
