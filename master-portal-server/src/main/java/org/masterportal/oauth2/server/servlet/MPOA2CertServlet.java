package org.masterportal.oauth2.server.servlet;

import java.security.GeneralSecurityException;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2CertServlet;

public class MPOA2CertServlet extends OA2CertServlet {

	@Override
	protected void checkMPConnection(OA2ServiceTransaction st) throws GeneralSecurityException {
        if (!hasMPConnection(st)) {
            debug("Creting new MP connection with username: " + st.getUsername() + " and lifetime: " + st.getLifetime());
            createMPConnection(st.getIdentifier(), st.getUsername(), "aaaaaa", st.getLifetime());
        }
    }

}
