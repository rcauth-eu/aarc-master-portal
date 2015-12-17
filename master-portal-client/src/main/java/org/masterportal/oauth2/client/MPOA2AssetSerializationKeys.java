package org.masterportal.oauth2.client;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2AssetSerializationKeys;

public class MPOA2AssetSerializationKeys extends OA2AssetSerializationKeys {

	String request_state = "request_state";
	String request_code = "request_code";
	
	public String request_state(String... x){
        if(0 < x.length) request_state = x[0];
        return request_state;
    }
	
	public String request_code(String... x){
        if(0 < x.length) request_code = x[0];
        return request_code;
    }	
	
}
