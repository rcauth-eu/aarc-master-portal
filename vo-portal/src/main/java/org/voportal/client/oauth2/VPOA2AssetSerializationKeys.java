package org.voportal.client.oauth2;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2AssetSerializationKeys;

public class VPOA2AssetSerializationKeys extends OA2AssetSerializationKeys {

	String voms_fqan = "voms_fqan";
    
	public String voms_fqan(String... x){
        if(0 < x.length) voms_fqan = x[0];
        return voms_fqan;
    }
	
}
