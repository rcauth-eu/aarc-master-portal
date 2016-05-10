package org.masterportal.oauth2.server.servlet;

import org.masterportal.oauth2.server.MPOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServlet;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;

public class MPOA2AuthorizedServlet extends OA2AuthorizedServlet {

	/**
	 *  return a MPOA2ServiceTransaction instance instead of OA2ServiceTransaction 
	 */
	@Override
	protected OA2ServiceTransaction createNewTransaction(AuthorizationGrant grant) {
		return new MPOA2ServiceTransaction(grant);
	}
	
}
