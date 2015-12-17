package org.masterportal.oauth2.client.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreUtil;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.masterportal.oauth2.client.MPOA2Asset;


public class MPOA2ForwardingStartRequest extends ClientServlet {
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
    	
    	info("1.a. Starting transaction");
        
        OA4MPResponse gtwResp = null;
        // Drumroll please: here is the work for this call.
       
        Identifier id = AssetStoreUtil.createID();
        gtwResp = getOA4MPService().requestCert(id);
        
    	// The MP-Server has to be able to identify its pending authentication session when
    	// the MP-Client returns an authenticated username. For this reason, the code&state 
    	// pair set by MP-Server/authorized for the incoming /authorize request is sent and
    	// saved at the beginning of the MP-Client session. The MPOA2ForwardingReadyServlet 
    	// will send the code&state pair together with the authenticated username back to 
    	// the MP-Server.
 
    	String code = (String) request.getAttribute("code");
    	String state = (String) request.getAttribute("state");    	
    	
    	if (code != null && state != null) {
    		
    		info("Saving code&state into asset store for later forwarding !");
    		MPOA2Asset asset = (MPOA2Asset) getCE().getAssetStore().get(id);
    		asset.setRequest_code(code);
    		asset.setRequest_state(state);
    		
    		//asset.set
    		
    		getCE().getAssetStore().save(asset);
    		
    	} else {
    		error("No code&state pair received! MP-Server will be unable to continue its pending auth request!");
    	}
    	
        // if there is a store, store something in it.
        Cookie cookie = new Cookie(OA4MP_CLIENT_REQUEST_ID, id.getUri().toString());
        cookie.setMaxAge(15 * 60); // 15 minutes
        cookie.setSecure(true);
        cookie.setPath("/mp-oa2-client");
        debug("id = " + id.getUri());
        response.addCookie(cookie);
        info("1.b. Got response. Creating page with redirect for " + gtwResp.getRedirect().getHost());
        
        response.sendRedirect(gtwResp.getRedirect().toString());
    }

}
