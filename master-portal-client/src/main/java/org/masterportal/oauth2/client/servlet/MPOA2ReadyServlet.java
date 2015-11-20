package org.masterportal.oauth2.client.servlet;


import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.servlet.JSPUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import org.gridforum.jgss.ExtendedGSSCredential;
import org.masterportal.myproxy.MPCredStoreService;
import org.masterportal.myproxy.exception.MyProxyCertExpiredExcpetion;
import org.masterportal.myproxy.exception.MyProxyNoUserException;
import org.masterportal.oauth2.client.MPOA2Asset;
import org.masterportal.oauth2.client.MPOA2MPService;

import java.io.FileOutputStream;
import java.net.URI;
import java.security.Principal;

public class MPOA2ReadyServlet extends ClientServlet {

	public static String PROXY_DIR = "/tmp";
	
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
        String identifier = clearCookie(request, response);
        MPOA2Asset asset = null;
        if (identifier == null) {
            asset = (MPOA2Asset) getCE().getAssetStore().getByToken(BasicIdentifier.newID(token));
            if (asset != null) {
                identifier = asset.getIdentifierString();
            }
        }
        
        AssetResponse assetResponse = null;
        UserInfo userInfo = null;
        MPOA2MPService oa2MPService = (MPOA2MPService) getOA4MPService();
        
        MPCredStoreService mpCredStoreService =  MPCredStoreService.getMPCredStoreService();
        
        GlobusGSSCredentialImpl userProxy = null;

        // we need an identifier in order to be able to save things into the asset store
        if (identifier == null) {
            error("no cookie found. Cannot save certificates");
            throw new GeneralException("no cookie found. Cannot save certificates");
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
            
            debug("2.a VOMS FQAN sent to MyProxy CredStore: " + asset.getVoms_fqan());
            
            boolean userCertValid = false;
            
            try {
            	debug("2.a Executing MyProxy INFO command");
            	MPCredStoreService.getMPCredStoreService().doInfo(asset.getUsername());
            	debug("2.a Valid user certificate found!");
            	userCertValid = true;
            } catch (MyProxyNoUserException e) {
            	debug("2.a No user found in MyProxy Credential Store!");
            	userCertValid = false;
            } catch (MyProxyCertExpiredExcpetion e) {
            	debug("2.a User certificate from MyProxy Credential Store is expired!");
            	userCertValid = false;
            }
            
        
            if (!userCertValid) {
            	
            	info("2.a. Proxy retrieval failed! Creating new user certificate ...");
            	
                info("2.a. Getting the cert(s) from the service");
                assetResponse = oa2MPService.getCert(asset, atResponse2);

            }
            
        	info("2.a.1 Trying to create proxy certificate for user");
        	userProxy = MPCredStoreService.getMPCredStoreService().doGet(asset.getUsername(),asset.getVoms_fqan());
        
        }
        
        // Again, we take the first returned cert to peel off some information to display. This
        // just proves we got a response.
        //X509Certificate cert = assetResponse.getX509Certificates()[0];

        Principal userDN = userProxy.getCertificateChain()[0].getSubjectDN();
        
        byte [] proxyData = ((ExtendedGSSCredential)userProxy).export(ExtendedGSSCredential.IMPEXP_OPAQUE);
        String proxyString = new String(proxyData);
        
        //export the user proxy into local storage so that the vo-portal can pick it up.
	    FileOutputStream fileOuputStream = new FileOutputStream(PROXY_DIR + "/" + asset.getUsername() + ".proxy"); 
	    fileOuputStream.write(proxyData);
	    fileOuputStream.close();
        
    	debug("Proxy Certificate in ReadyServlet returning to the user");
    	debug("###########  PROXY ###########");
    	debug( proxyString );
    	debug("###########  PROXY ###########");
    	
        info("2.b. Done! Displaying success page.");

        // Rest of this is putting up something for the user to see
        request.setAttribute("userSubject", asset.getUsername());
        request.setAttribute("certSubject", userDN);
        request.setAttribute("cert", proxyString);
        request.setAttribute("username", asset.getUsername());
        // Fix in cases where the server request passes through Apache before going to Tomcat.

        String contextPath = request.getContextPath();
        if (!contextPath.endsWith("/")) {
            contextPath = contextPath + "/";
        }
        request.setAttribute("action", contextPath);
        info("2.a. Completely finished with delegation.");
        JSPUtil.fwd(request, response, getCE().getSuccessPagePath());
    
        return;
		
	}

}
