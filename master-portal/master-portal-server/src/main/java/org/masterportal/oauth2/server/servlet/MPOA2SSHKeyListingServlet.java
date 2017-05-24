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
import java.io.IOException;
//import java.util.LinkedList;
import java.util.ArrayList;
import java.util.List;
import java.util.Collection;
import java.net.URI;

import java.util.Base64;

import java.io.Writer;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import static edu.uiuc.ncsa.security.core.util.DateUtils.checkTimestamp;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 */
public class MPOA2SSHKeyListingServlet extends MyProxyDelegationServlet {
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
	return null;
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
	MyLoggingFacade logger = new MyLoggingFacade(getClass().getSimpleName(), false);

	MPOA2SE se = (MPOA2SE)getServiceEnvironment();

	SQLSSHKeyStore store = (SQLSSHKeyStore)se.getSSHKeyStore();
	if ( store == null) {
	    throw new GeneralException("Could not get SSHKeyStore"); 
	}

	Collection<SSHKey> keys = store.values();
   
	Writer writer = response.getWriter();
	for (SSHKey key : keys)    {
	    writer.write(key.getUserName());
	    writer.write(",");
	    writer.write(key.getPubKey());
	    writer.write("\n");
	}
	writer.flush();
	writer.close();
    }

}
