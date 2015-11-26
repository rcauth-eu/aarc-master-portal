package edu.uiuc.ncsa.security.oauth_2_0.client;

import edu.uiuc.ncsa.security.delegation.client.request.PPResponse;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.MyX509Proxy;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.servlet.ServiceClient;

import java.util.HashMap;
import java.util.Map;

/**
 * Handles client call for protected proxy request, or just /getproxy request for short
 */
public class PPServer2 extends PAServer2 {

    public PPServer2(ServiceClient serviceClient) {
        super(serviceClient);
    }
	
	@Override
    protected PPResponse getAsset(Client client, Map props, AccessToken accessToken) {
        HashMap m = new HashMap();
        m.put(OA2Constants.ACCESS_TOKEN, accessToken.getToken().toString());
        m.put(OA2Constants.CLIENT_ID, client.getIdentifierString());
        m.put(OA2Constants.CLIENT_SECRET, client.getSecret());
        //m.put(OA2Constants.REDIRECT_URI,  props.get(OA2Constants.REDIRECT_URI));
        //m.put(OA2Constants.CERT_REQ, String.valueOf(props.get(AbstractClientEnvironment.CERT_REQUEST_KEY)));
        //m.put(OA2Constants.CERT_LIFETIME, String.valueOf(props.get(AbstractClientEnvironment.CERT_LIFETIME_KEY)));
        String response = getServiceClient().getRawResponse(m); // No JSON in the spec. Just a string of proxy.
        
        MyX509Proxy myX509Certificate = new MyX509Proxy(response.getBytes());

        PPResponse par = new PPResponse(myX509Certificate);
        return par;
    }
}
