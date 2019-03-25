package eu.rcauth.masterportal.client.servlet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;
import eu.rcauth.masterportal.MPClientContext;

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
 * MPClientContext.MP_CLIENT_REQUEST_ID. On success, this endpoint will take care of storing 
 * a Long Lived Proxy Certificate derived from the certificate returned from the 
 * Delegation Server, and return a success code to the MP Server. No actual credential is 
 * returned by this endpoint.
 * 
 * @see <a href="https://wiki.nikhef.nl/grid/Master_Portal_Internals">wiki</a>
 * 
 * @author "Tamás Balogh"
 *
 */
public class MPOA2ForwardingGetCertServer extends ClientServlet {

	@Override
	protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
		
		info("3.a Starting /getcert call to the Delegation Server");
    	
		OA2MPService oa2MPService = (OA2MPService) getOA4MPService();
		
		// get the session identifier from the request
		String identifier = (String) request.getAttribute(MPClientContext.MP_CLIENT_REQUEST_ID);
		
		if (identifier == null) {
            
			error("Identifier not found in cookies! Cannot get the transaction asset");
			response.sendError(HttpStatus.SC_INTERNAL_SERVER_ERROR);
			// This is not very clean: we should probably send headers and
			// format too, but at least we can get the error accross to the
			// server-side.
			response.getWriter().write("Identifier not found in cookies! Cannot get the transaction asset");
			response.getWriter().flush();
			
        } else {
        	
        	info("3.a Received a session identifier : " + identifier);
        	
        	OA2Asset asset = (OA2Asset) getCE().getAssetStore().get(identifier);
        	
        	ATResponse2 atResponse2 = new ATResponse2(asset.getAccessToken(), asset.getRefreshToken());
        	AssetResponse assetResponse  = oa2MPService.getCert(asset, atResponse2);
       	
        	info("3.c Successfuly completed /getcert call");
        	
        	// set status code, so the calling OA4MP Server will know that the call succeeded. 
        	response.setStatus(HttpStatus.SC_OK);
        }
		
	}

}
