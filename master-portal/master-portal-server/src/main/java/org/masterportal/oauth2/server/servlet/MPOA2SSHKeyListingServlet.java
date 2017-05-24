package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import org.masterportal.oauth2.server.storage.SSHKey;
import org.masterportal.oauth2.server.storage.SSHKeyIdentifier;
import org.masterportal.oauth2.server.storage.sql.SQLSSHKeyStore;

import edu.uiuc.ncsa.security.delegation.storage.Client;

import org.masterportal.oauth2.server.MPOA2SE;

//import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;

import edu.uiuc.ncsa.security.oauth_2_0.OA2Utilities;
//import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandler;
//import edu.uiuc.ncsa.security.oauth_2_0.server.UII2;
//import edu.uiuc.ncsa.security.oauth_2_0.server.UIIRequest2;
//import edu.uiuc.ncsa.security.oauth_2_0.server.UIIResponse2;

import org.apache.commons.codec.digest.DigestUtils;


import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.CLIENT_SECRET;
import static edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys.CONSUMER_KEY;
import org.apache.http.HttpStatus;

import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.Identifier;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.Collection;

import java.io.Writer;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;


/**
 * <p>Created by Mischa Sall&eacute;<br>
 */
public class MPOA2SSHKeyListingServlet extends MyProxyDelegationServlet {
    private MPOA2SE se;
    private MyLoggingFacade logger;

    @Override
    public void init() throws ServletException	{
	super.init();
	se = (MPOA2SE)getServiceEnvironment();
	setEnvironment(se);

	// Create custom logger for exceptions and the like
//	logger = new MyLoggingFacade(getClass().getSimpleName(), false);
	logger = getMyLogger();
	setExceptionHandler(new OA2ExceptionHandler(logger));
    }

    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
	return null;
    }

    @Override
    protected void handleException(Throwable t, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
	// ok, if it is a strange error, print a stack if you need to.
	// Note: getMyLogger gives logger from environment, which is configured
	// via conf file and logs typically into mp server logs, not in
	// /var/log/messages
        if (logger.isDebugOn()) {
            t.printStackTrace();
        }
	getExceptionHandler().handleException(t, request, response);
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
	
	SQLSSHKeyStore store = (SQLSSHKeyStore)se.getSSHKeyStore();
	if ( store == null) {
	    throw new GeneralException("Could not get SSHKeyStore"); 
	}

	Collection<SSHKey> keys = store.values();
   
	Writer writer = response.getWriter();
	for (SSHKey key : keys)    {
	    writer.write(key.getUserName());
	    writer.write(" ");
	    writer.write(key.getPubKey());
	    writer.write("\n");
	}
	writer.flush();
	writer.close();
    }
}
