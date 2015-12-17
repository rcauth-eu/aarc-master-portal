package org.masterportal.server.oauth2.servlet;


import java.security.GeneralSecurityException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.myproxy.exception.MyProxyCertExpiredExcpetion;
import edu.uiuc.ncsa.myproxy.exception.MyProxyNoUserException;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ProxyServlet;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;

import org.masterportal.server.oauth2.MPOA2SE;
import org.masterportal.server.oauth2.MPOA2ServiceTransaction;

public class MPOA2ProxyServlet extends OA2ProxyServlet {

	public static final String MP_CLIENT_CONTEXT = "/mp-oa2-client";
	public static final String MP_CLIENT_FORWARD_GETCERT = "/forwardgetcert";
	
	@Override
	protected void checkMPConnection(OA2ServiceTransaction st) throws GeneralSecurityException {
        if (!hasMPConnection(st)) {
        	String myproxyPasswrod  = ((MPOA2SE)getServiceEnvironment()).getMyproxyPassword();
        	debug("Creting new MP connection with username: " + st.getUsername() + " and lifetime: " + st.getLifetime());
            createMPConnection(st.getIdentifier(), st.getUsername(), myproxyPasswrod, st.getLifetime());
        }
	}
	
	@Override
	protected void prepare(ServiceTransaction transaction, HttpServletRequest request, HttpServletResponse response) throws Throwable {
		super.prepare(transaction, request, response);
		
		OA2ServiceTransaction trans = (OA2ServiceTransaction)transaction;
		
		checkMPConnection(trans);
        MyProxyConnectable mpc = getMPConnection(trans);
        
        
        
	    boolean userCertValid = false;
	    
        try {
	        
        	info("Executing MyProxy INFO");
	        String info = mpc.doInfo();
	        debug("Valid user certificate found!");
	        
	        debug("--- INFO ---");
	        debug(info);
	        debug("--- INFO ---");
	        userCertValid = true;
	        
        } catch (MyProxyNoUserException e) {
        	debug("No user found in MyProxy Credential Store!");
        	userCertValid = false;
        }
        catch (MyProxyCertExpiredExcpetion e) {
        	debug("User certificate from MyProxy Credential Store is expired!");
        	userCertValid = false;
        }
        
        if (!userCertValid) {
        
        	info("2.a. Proxy retrieval failed! Creating new user certificate ...");
        	// call /forwardetproxy on the Master Portal Client component
        	forwardRealCertRequest(trans, request, response);
        	
        }
        		
        		
	}

	protected void forwardRealCertRequest(ServiceTransaction trans, HttpServletRequest request, HttpServletResponse response) throws Throwable {
			
		info("Forwarding getCert request to Master Portal Client");
		
		// extract client session ID and send it along with the request
		String clientID = ((MPOA2ServiceTransaction)trans).getClientSessionIdentifier();
		request.setAttribute("identifier", clientID);
		
		// forward request to MP-Client
		ServletContext serverContext = getServletConfig().getServletContext();
		ServletContext clientContext = serverContext.getContext(MP_CLIENT_CONTEXT);
     
		RequestDispatcher dispatcher = clientContext.getRequestDispatcher(MP_CLIENT_FORWARD_GETCERT);
		// use include instead of forward here so that the responses returned to the requester will be aggregated
		dispatcher.include( request , response );        
		
	    info("Ended forwarding getCert to Master Portal Client");
	    
	}
	
}
