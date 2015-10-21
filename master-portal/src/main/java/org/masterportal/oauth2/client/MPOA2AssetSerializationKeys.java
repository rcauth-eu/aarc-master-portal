package org.masterportal.oauth2.client;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2AssetSerializationKeys;

public class MPOA2AssetSerializationKeys extends OA2AssetSerializationKeys {

	String voms_fqan = "voms_fqan";
    
	public String voms_fqan(String... x){
        if(0 < x.length) voms_fqan = x[0];
        return voms_fqan;
    }
	
}
