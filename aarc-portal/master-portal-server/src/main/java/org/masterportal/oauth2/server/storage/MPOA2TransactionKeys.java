package org.masterportal.oauth2.server.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionKeys;

public class MPOA2TransactionKeys extends OA2TransactionKeys {

	public MPOA2TransactionKeys() {
		super();
	}
	
    protected String mp_client_session_identifier = "mp_client_session_identifier";
	
    public String mp_client_session_identifier(String... x) {
        if (0 < x.length) mp_client_session_identifier = x[0];
        return mp_client_session_identifier;
    }
}
