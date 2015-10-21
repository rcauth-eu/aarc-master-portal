package org.masterportal.oauth2.client.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreUtil;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.masterportal.oauth2.client.MPOA2Asset;


public class MPOA2StartRequest extends ClientServlet {
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
    	
    	info("1.a. Starting transaction");
        
        OA4MPResponse gtwResp = null;
        // Drumroll please: here is the work for this call.
        Identifier id = AssetStoreUtil.createID();
        gtwResp = getOA4MPService().requestCert(id);
        
        
    	String vomsFQAN = request.getParameter("voms_fqan");
    	
    	if (vomsFQAN == null) {
    		info("1.a.1 No voms fqan received, continuing without it");
    	} else {
    		info("1.a.1 voms fqan received : " + vomsFQAN);
    		
    		System.out.println("MPOA2StartRequest id: " + id );
    		System.out.println("MPOA2StartRequest id: " + id.getUri() );
    		
    		MPOA2Asset asset = (MPOA2Asset) getCE().getAssetStore().get(id);
    		asset.setVoms_fqan(vomsFQAN);
    		getCE().getAssetStore().save(asset);
    	}        
        
        // if there is a store, store something in it.
        Cookie cookie = new Cookie(OA4MP_CLIENT_REQUEST_ID, id.getUri().toString());
        cookie.setMaxAge(15 * 60); // 15 minutes
        cookie.setSecure(true);
        debug("id = " + id.getUri());
        response.addCookie(cookie);
        info("1.b. Got response. Creating page with redirect for " + gtwResp.getRedirect().getHost());
        
        response.sendRedirect(gtwResp.getRedirect().toString());
    }

}
