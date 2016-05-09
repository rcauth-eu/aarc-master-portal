package org.voportal.client.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreUtil;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A simple servlet that starts the request. It will make the initial request and set an identifier
 * cookie in the users browser. If there is an {@link edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore} configured, it will make
 * an entry for the {@link edu.uiuc.ncsa.myproxy.oa4mp.client.Asset} resulting from this delegation.
 * <br><br>
 * This example is intended to show control flow rather than be a polished application.
 * Feel free to boilerplate from it as needed. Do not deploy this in production environments.
 * <p>Created by Jeff Gaynor<br>
 * on 2/10/12 at  10:24 AM
 */
public class VPOA2StartRequest extends ClientServlet {
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        info("1.a. Starting transaction");
        OA4MPResponse gtwResp = null;
        // Drumroll please: here is the work for this call.
        Identifier id = AssetStoreUtil.createID();
        gtwResp = getOA4MPService().requestCert(id);

        // save VO parameters so that we can send them in a subsequent /getproxy call
    	String voname = request.getParameter(OA2Constants.VONAME);
    	if (voname == null) {
    		info("1.a.1 No voname, continuing without it");
    	} else {
    		info("1.a.1 voname received : " + voname);
    		OA2Asset asset = (OA2Asset) getCE().getAssetStore().get(id);
    		asset.setVoname(voname);
    		getCE().getAssetStore().save(asset);
    	}          
    	String vomses = request.getParameter(OA2Constants.VOMSES);
    	if (vomses == null) {
    		info("1.a.1 No vomses, continuing without it");
    	} else {
    		info("1.a.1 vomses received : " + vomses);
    		OA2Asset asset = (OA2Asset) getCE().getAssetStore().get(id);
    		asset.setVomses(vomses);
    		getCE().getAssetStore().save(asset);
    	}          
    	
    	
        // if there is a store, store something in it.
        Cookie cookie = new Cookie(OA4MP_CLIENT_REQUEST_ID, id.getUri().toString());
        cookie.setMaxAge(15 * 60); // 15 minutes
        cookie.setSecure(true);
        debug("id = " + id.getUri());
        response.addCookie(cookie);
        info("1.b. Got response. Creating page with redirect for " + gtwResp.getRedirect().getHost());
        if (getCE().isShowRedirectPage()) {
            request.setAttribute(REDIR, REDIR);
            request.setAttribute("redirectUrl", gtwResp.getRedirect().toString());
            //request.setAttribute("privateKey", KeyUtil.toPKCS8PEM(gtwResp.getPrivateKey()));
            request.setAttribute(ACTION_KEY, ACTION_KEY);
            request.setAttribute("action", ACTION_REDIRECT_VALUE);

            // Normally, we'd just do a redirect, but we will put up a page and show the redirect to the user.
            // The client response contains the generated private key as well
            // In a real application, the private key would be stored. This, however, exceeds the scope of this
            // sample application -- all we need to do to complete the process is send along the redirect url.

            info("1.b. Showing redirect page.");
            JSPUtil.fwd(request, response, getCE().getRedirectPagePath());
            return;
        }
        response.sendRedirect(gtwResp.getRedirect().toString());
    }

}
