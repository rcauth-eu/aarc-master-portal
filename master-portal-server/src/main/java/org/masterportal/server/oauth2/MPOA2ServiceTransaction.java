package org.masterportal.server.oauth2;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;

public class MPOA2ServiceTransaction extends OA2ServiceTransaction {
	
	public MPOA2ServiceTransaction(AuthorizationGrant ag) {
		super(ag);
	}
	
    public MPOA2ServiceTransaction(Identifier identifier) {
        super(identifier);
    }

    String clientSessionIdentifier;
    
    public String getClientSessionIdentifier() {
		return clientSessionIdentifier;
	}
    
    public void setClientSessionIdentifier(String clientSessionIdentifier) {
		this.clientSessionIdentifier = clientSessionIdentifier;
	}
    
}
