package org.masterportal.server.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionKeys;

public class MPOA2TransactionKeys extends OA2TransactionKeys {

	public MPOA2TransactionKeys() {
		super();
	}
	
    protected String clientSessionIdentifier = "client_session_identifier";
	
    public String clientSessionIdentifier(String... x) {
        if (0 < x.length) clientSessionIdentifier = x[0];
        return clientSessionIdentifier;
    }
}
