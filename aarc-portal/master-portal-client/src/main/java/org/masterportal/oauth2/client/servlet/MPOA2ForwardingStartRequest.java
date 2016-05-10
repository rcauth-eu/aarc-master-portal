package org.masterportal.oauth2.client.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreUtil;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;
import org.masterportal.oauth2.MPClientContext;
import org.masterportal.oauth2.MPServerContext;
import org.masterportal.oauth2.client.MPOA2Asset;

/**
 * Simple /startRequest implementation that supports session keeping between the 
 * MP Server and MP Client. It strips the 'code' and 'server' received as request
 * attributes and saves them for the purpose of session keeping on the MP Server.
 * In case any of the above mentioned attributes are missing the request will fail
 * since the originating MP Server session can no longer be identified by the 
 * MP Client.  
 * <p>
 * Afterwards, it continues to redirect to the service url of the configured
 * Delegation Server, just like a normal /startRequest would.
 * 
 * @author "Tamás Balogh"
 *
 */
public class MPOA2ForwardingStartRequest extends ClientServlet {
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
    	
    	info("1.a. Starting transaction");
        
        OA4MPResponse gtwResp = null;
        // Drumroll please: here is the work for this call.
       
        Identifier id = AssetStoreUtil.createID();
        gtwResp = getOA4MPService().requestCert(id);
        
        /* EXTRACT 'code' AND 'state' */
        
    	// The MP-Server has to be able to identify its pending authentication session when
    	// the MP-Client returns an authenticated username. For this reason, the code&state 
    	// pair set by MP-Server/authorized for the incoming /authorize request is sent and
    	// saved at the beginning of the MP-Client session. The MPOA2ForwardingReadyServlet 
    	// will send the code&state pair together with the authenticated username back to 
    	// the MP-Server.
 
    	String code = (String) request.getAttribute(MPServerContext.MP_SERVER_AUTHORIZE_CODE);
    	String state = (String) request.getAttribute(MPServerContext.MP_SERVER_AUTHORIZE_STATE);    	
    	
    	if (code != null && state != null) {
    		
    		info("Saving code&state into asset store for later forwarding !");
    		MPOA2Asset asset = (MPOA2Asset) getCE().getAssetStore().get(id);
    		asset.setMPServerRequestCode(code);
    		asset.setMPServerRequestState(state);
    	
    		getCE().getAssetStore().save(asset);
    		
    	} else {
    		error("No code&state pair received! MP-Server will be unable to continue its pending auth request!");
    		throw new OA2RedirectableError("No code or state received! MP-Server will be unable to continue its pending auth request!");
    	}

        /* CONTINUE WITH REGULAR REDIRECT TO DELEGATION SERVER */
    	
        // if there is a store, store something in it.
        Cookie cookie = new Cookie(MPClientContext.MP_CLIENT_REQUEST_ID, id.getUri().toString());
        cookie.setMaxAge(15 * 60); // 15 minutes
        cookie.setSecure(true);
        cookie.setPath(MPClientContext.MP_CLIENT_CONTEXT);
        debug("id = " + id.getUri());
        response.addCookie(cookie);
        info("1.b. Got response. Creating page with redirect for " + gtwResp.getRedirect().getHost());
        
        response.setStatus(HttpStatus.SC_OK);
        response.sendRedirect(gtwResp.getRedirect().toString());
    }

}
