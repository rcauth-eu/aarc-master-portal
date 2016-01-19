package org.masterportal.oauth2.client.servlet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;

public class MPOA2ForwardingGetCertServer extends ClientServlet {

	@Override
	protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
		
		OA2MPService oa2MPService = (OA2MPService) getOA4MPService();
		
		String identifier = (String) request.getAttribute("identifier");
		
		if (identifier == null) {
            
			error("Identifier not found in cookies! Cannot get the transaction asset");	
			
        } else {
        	
        	info("Received a session identifier : " + identifier);
        	
        	OA2Asset asset = (OA2Asset) getCE().getAssetStore().get(identifier);
        	
        	ATResponse2 atResponse2 = new ATResponse2(asset.getAccessToken(), asset.getRefreshToken());
        	AssetResponse assetResponse  = oa2MPService.getCert(asset, atResponse2);
       	
        	// set status code, so the calling OA4MP Server will know that the call sucseeded. 
        	response.setStatus(HttpStatus.SC_OK);
        }
		
	}

}
