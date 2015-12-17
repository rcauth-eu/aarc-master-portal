package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetSerializationKeys;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/20/14 at  2:22 PM
 */
public class OA2AssetSerializationKeys extends AssetSerializationKeys {

	String voname = "voname";
	public String voname(String... x){
        if(0 < x.length) voname = x[0];
        return voname;
    }

	String vomses = "vomses";
	public String vomses(String... x){
        if(0 < x.length) vomses = x[0];
        return vomses;
    }
	
    String accessToken = "access_token";
    public String accessToken(String... x){
        if(0 < x.length) accessToken= x[0];
        return accessToken;
    }

    String refreshToken  = "refresh_token";
    public String refreshToken(String... x){
        if(0 < x.length) refreshToken = x[0];
        return refreshToken;
    }

    String refreshLifetime = "refresh_lifetime";
    public String refreshLifetime(String... x){
        if(0 < x.length) refreshLifetime = x[0];
        return refreshLifetime;
    }

    String state = "state";
    public String state(String... x){
        if(0 < x.length) state = x[0];
        return state;
    }

    String nonce="nonce";
    public String nonce(String... x){
        if(0 < x.length) nonce = x[0];
        return nonce;
    }
    String issuedAt = "issuedAt";
    public String issuedAt(String... x){
        if(0 < x.length) issuedAt = x[0];
        return issuedAt;
    }


}
