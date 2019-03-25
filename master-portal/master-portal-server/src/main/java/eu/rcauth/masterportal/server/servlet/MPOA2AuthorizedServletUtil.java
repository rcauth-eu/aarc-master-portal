package eu.rcauth.masterportal.server.servlet;

import eu.rcauth.masterportal.server.MPOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServletUtil;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;

public class MPOA2AuthorizedServletUtil extends OA2AuthorizedServletUtil {

    public MPOA2AuthorizedServletUtil(MyProxyDelegationServlet servlet) {
        super(servlet);
    }

    /**
     *  return a MPOA2ServiceTransaction instance instead of OA2ServiceTransaction 
     */
    @Override
    protected OA2ServiceTransaction createNewTransaction(AuthorizationGrant grant) {
        return new MPOA2ServiceTransaction(grant);
    }

}
