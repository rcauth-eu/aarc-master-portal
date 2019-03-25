package eu.rcauth.masterportal.client.storage;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2AssetSerializationKeys;

public class MPOA2AssetSerializationKeys extends OA2AssetSerializationKeys {

	String mp_server_request_state = "mp_server_request_state";
	String mp_server_request_code = "mp_server_request_code";
	
	public String mp_server_request_state(String... x){
        if(0 < x.length) mp_server_request_state = x[0];
        return mp_server_request_state;
    }
	
	public String mp_server_request_code(String... x){
        if(0 < x.length) mp_server_request_code = x[0];
        return mp_server_request_code;
    }	
	
}
