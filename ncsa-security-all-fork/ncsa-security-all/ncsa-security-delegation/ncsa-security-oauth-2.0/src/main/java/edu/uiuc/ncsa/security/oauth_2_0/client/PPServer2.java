package edu.uiuc.ncsa.security.oauth_2_0.client;

import edu.uiuc.ncsa.security.delegation.client.request.PAResponse;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.MyX509Proxy;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.servlet.ServiceClient;

import java.util.HashMap;
import java.util.Map;

/**
 * Handles client call for protected proxy request, or just /getproxy request for short
 * <p>Created by Tamas Balogh<br>
 */
public class PPServer2 extends PAServer2 {

    public PPServer2(ServiceClient serviceClient) {
        super(serviceClient);
    }
	
	@Override
    protected PAResponse getAsset(Client client, Map props, AccessToken accessToken) {
        HashMap m = new HashMap();
        m.put(OA2Constants.ACCESS_TOKEN, accessToken.getToken().toString());
        m.put(OA2Constants.CLIENT_ID, client.getIdentifierString());
        m.put(OA2Constants.CLIENT_SECRET, client.getSecret());
        
        // add optional VO parameters in case they are given
        if ( props.containsKey(OA2Constants.VONAME) ) {
        	m.put(OA2Constants.VONAME, props.get(OA2Constants.VONAME));
        }
        if ( props.containsKey(OA2Constants.VOMSES) ) {
        	m.put(OA2Constants.VOMSES, props.get(OA2Constants.VOMSES));
        }
        
        m.put(OA2Constants.PROXY_LIFETIME, String.valueOf(props.get(OA2Constants.PROXY_LIFETIME)));
        String response = getServiceClient().getRawResponse(m);     
        
        MyX509Proxy myX509Certificate = new MyX509Proxy(response.getBytes());

        PAResponse par = new PAResponse(myX509Certificate);
        return par;
    }
}
