package org.masterportal.oauth2.client.servlet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;
import org.masterportal.oauth2.MPClientContext;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;

/**
 * This servlet implements the /forwardGetCert endpoint. This endpoint was introduced 
 * as an internal endpoint and only meant to be called from the MP Server. 
 * <p>
 * Calling this endpoint initiates a /getcert request issued to the Delegation Server.
 * Note that for this to work, you need to have a valid session identified by the 
 * {@link MP_CLIENT_REQUEST_ID}. On success, this endpoint will take care of storing 
 * a Long Lived Proxy Certificate derived from the certificate returned from the 
 * Delegation Server, and return a success code to the MP Server. No actual credential is 
 * returned by this endpoint.
 * 
 * @see https://wiki.nikhef.nl/grid/Master_Portal_Internals
 * 
 * @author "Tamás Balogh"
 *
 */
public class MPOA2ForwardingGetCertServer extends ClientServlet {

	@Override
	protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
		
		OA2MPService oa2MPService = (OA2MPService) getOA4MPService();
		
		// get the session identifier from the request
		String identifier = (String) request.getAttribute(MPClientContext.MP_CLIENT_REQUEST_ID);
		
		if (identifier == null) {
            
			error("Identifier not found in cookies! Cannot get the transaction asset");	
			
        } else {
        	
        	info("Received a session identifier : " + identifier);
        	
        	OA2Asset asset = (OA2Asset) getCE().getAssetStore().get(identifier);
        	
        	ATResponse2 atResponse2 = new ATResponse2(asset.getAccessToken(), asset.getRefreshToken());
        	AssetResponse assetResponse  = oa2MPService.getCert(asset, atResponse2);
       	
        	// set status code, so the calling OA4MP Server will know that the call succeeded. 
        	response.setStatus(HttpStatus.SC_OK);
        }
		
	}

}
