package org.masterportal.oauth2.client.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.servlet.JSPUtil;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.masterportal.oauth2.MPServerContext;
import org.masterportal.oauth2.client.MPOA2Asset;
import org.masterportal.oauth2.client.MPOA2MPService;

import java.net.URI;

public class MPOA2ForwardingReadyServlet extends ClientServlet {
	
	@Override
	protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {

       if (request.getParameterMap().containsKey(OA2Constants.ERROR)) {
            throw new OA2RedirectableError(request.getParameter(OA2Constants.ERROR),
                    request.getParameter(OA2Constants.ERROR_DESCRIPTION),
                    request.getParameter(OA2Constants.STATE));
        }

        // Get the cert itself. The server itself does a redirect using the callback to this servlet
        // (so it is the portal that actually is invoking this method after the authorization
        // step.) The token and verifier are peeled off and used
        // to complete the request.
        info("2.a. Getting token and verifier.");
        String token = request.getParameter(CONST(ClientEnvironment.TOKEN));
        String state = request.getParameter(OA2Constants.STATE);
        if (token == null) {
            warn("2.a. The token is " + (token == null ? "null" : token) + ".");
            GeneralException ge = new GeneralException("Error: This servlet requires parameters for the token and possibly verifier.");
            request.setAttribute("exception", ge);
            JSPUtil.fwd(request, response, getCE().getErrorPagePath());
            return;
        }
        info("2.a Token found.");

        AuthorizationGrant grant = new AuthorizationGrantImpl(URI.create(token));
        //String identifier = getIdentifierCookie(request, response);
        String identifier = clearCookie(request, response);
        MPOA2Asset asset = null;
        if (identifier == null) {
        	System.out.println("Getting Asset from token: " + token);
            asset = (MPOA2Asset) getCE().getAssetStore().getByToken(BasicIdentifier.newID(token));
            System.out.println("Getting Asset: " + asset);
            if (asset != null) {
                identifier = asset.getIdentifierString();
                System.out.println("Getting identifier: " + identifier);
            }
        }
        
        AssetResponse assetResponse = null;
        UserInfo userInfo = null;
        OA2MPService oa2MPService = (OA2MPService) getOA4MPService();
        
        //MPCredStoreService mpCredStoreService =  MPCredStoreService.getMPCredStoreService();
       // GlobusGSSCredentialImpl userProxy = null;

        // we need an identifier in order to be able to save things into the asset store
        if (identifier == null) {
            error("no cookie found. Cannot save certificates");
            throw new GeneralException("no session cookie found. Cannot save certificates");
        } else {
            asset = (MPOA2Asset) getCE().getAssetStore().get(identifier);
            if(!asset.getState().equals(state)){
                warn("The expected state from the server was \"" + asset.getState() + "\", but instead \"" + state + "\" was returned. Transaction aborted.");
                throw new IllegalArgumentException("Error: The state returned by the server is invalid.");
            }
            ATResponse2 atResponse2 = oa2MPService.getAccessToken(asset, grant);
            
            info("2.a Getting user info.");
            userInfo = oa2MPService.getUserInfo(identifier);
            
            if (userInfo == null) {
            	error("2.a Could not get userinfo");
            	throw new GeneralException("User subject could not be extracted! The userinfo endpoint returned null!");
            }

            // Something is already setting the Asset username to the value returned by the userinfo endpoint.
            // Look for getAdditionalInformation() calls in getCert requests. This here might be redundant.
            // With the current implementation the getCert request returns the username in the additional
            // information map.
            debug("2.a Getting username from /userInfo");
            String userSubject = userInfo.getSub();
            asset.setUsername(userSubject);
            
            //info("2.a. Getting the cert(s) from the service");
            //assetResponse = oa2MPService.getCert(asset, atResponse2);
            
            String reqState = asset.getRequest_state();
            String reqCode = asset.getRequest_code();
            
            debug("Forwarding back to MP-Server with code : " + reqCode + " state : " + reqState + " and username: " + userSubject);
            
            //request.setAttribute("mpclient_session_id", identifier);
            
            request.setAttribute(MPServerContext.MP_SERVER_AUTHORIZE_CODE, reqCode);
            request.setAttribute(MPServerContext.MP_SERVER_AUTHORIZE_STATE, reqState);
            request.setAttribute(MPServerContext.MP_SERVER_AUTHORIZE_USERNAME, userSubject);
            request.setAttribute(MPServerContext.MP_SERVER_AUTHORIZE_ACTION, MPServerContext.MP_SERVER_AUTHORIZE_ACTION_OK);
            
            ServletContext serverContext = getServletConfig().getServletContext();
            ServletContext clientContext = serverContext.getContext(MPServerContext.MP_SERVER_CONTEXT);
             
            RequestDispatcher dispatcher = clientContext.getRequestDispatcher(MPServerContext.MP_SERVER_AUTHORIZE_ENDPOINT);
            dispatcher.forward(request, response);
            
        }
        
        return;
		
	}
	
}
