package org.voportal.client.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPProxyService;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.MyX509Proxy;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.servlet.JSPUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.voportal.voms.VPVomsProxyInfo;

import java.io.File;
import java.io.FileOutputStream;
import java.net.URI;

public class VPOA2ReadyServlet extends ClientServlet {
	
	protected static String PROXY_TMP_DIR = "/tmp";
	public static String VOMS_INFO_PAGE = "/pages/vomsinfo.jsp";
	
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
        info("2.a. Getting the cert(s) from the service");
        String identifier = clearCookie(request, response);
        OA2Asset asset = null;
        if (identifier == null) {
            asset = (OA2Asset) getCE().getAssetStore().getByToken(BasicIdentifier.newID(token));
            if (asset != null) {
                identifier = asset.getIdentifierString();
            }
        }
        AssetResponse assetResponse = null;
        OA2MPProxyService oa2MPService = (OA2MPProxyService) getOA4MPService();

        UserInfo ui = null;
        if (identifier == null) {
            
        	debug("No cookie found! Cannot identify session!");
            throw new GeneralException("Unable to identify session!");
            
        } else {
            asset = (OA2Asset) getCE().getAssetStore().get(identifier);
            if(asset.getState() == null || !asset.getState().equals(state)){
                warn("The expected state from the server was \"" + asset.getState() + "\", but instead \"" + state + "\" was returned. Transaction aborted.");
                throw new IllegalArgumentException("Error: The state returned by the server is invalid.");
            }
            ATResponse2 atResponse2 = oa2MPService.getAccessToken(asset, grant);
            ui = oa2MPService.getUserInfo(identifier);
            assetResponse = oa2MPService.getProxy(asset, atResponse2);
        }
        
        info("2.b. Done! Displaying VOMS INFO.");

        String username = ui.getSub().replaceAll("/", "X");
        String tmpProxy = PROXY_TMP_DIR + "/" + username + ".proxy";
		String proxyString = null;
		
		if ( assetResponse.getCredential() instanceof MyX509Proxy ) {
			proxyString = ((MyX509Proxy)assetResponse.getCredential()).getX509ProxyPEM();
		} else {
			proxyString = assetResponse.getCredential().getX509CertificatesPEM();
		}
		
        String vomsinfo = null;
		
		try {
			FileOutputStream fOut = new FileOutputStream(new File(tmpProxy));
			fOut.write( proxyString.getBytes() );
			fOut.close();
			
			vomsinfo = VPVomsProxyInfo.exec(tmpProxy);
		}
		catch (Exception e) {
			throw new GeneralException("Unable to execute voms-proxy-info on the returned chain!",e);
		}        
        
		request.setAttribute("vomsinfo", vomsinfo);
		request.setAttribute("proxy", proxyString);

		// Fix in cases where the server request passes through Apache before going to Tomcat.

        String contextPath = request.getContextPath();
        if (!contextPath.endsWith("/")) {
            contextPath = contextPath + "/";
        }
        info("2.a. Completely finished with delegation.");
        JSPUtil.fwd(request, response, VOMS_INFO_PAGE);       
        
        
        return;
    }

}
