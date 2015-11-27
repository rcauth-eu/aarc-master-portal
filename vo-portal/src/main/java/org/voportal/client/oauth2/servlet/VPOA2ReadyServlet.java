package org.voportal.client.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
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
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.voportal.client.ProxyAssetResponse;
import org.voportal.client.oauth2.VPOA2Asset;
import org.voportal.client.oauth2.VPOA2MPService;

import java.net.URI;
import java.security.cert.X509Certificate;

/**
 * A very, very simple (as in stupid) ready servlet. This is the target of the callback uri supplied in
 * the initial request. <br><br>This example is intended to show control flow rather than be a polished application.
 * Feel free to boilerplate from it as needed. Do not deploy this in production environments.
 * <p>Created by Jeff Gaynor<br>
 * <p/>
 * on 2/10/12 at  1:43 PM
 */

public class VPOA2ReadyServlet extends ClientServlet {
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
        VPOA2Asset asset = null;
        if (identifier == null) {
            asset = (VPOA2Asset) getCE().getAssetStore().getByToken(BasicIdentifier.newID(token));
            if (asset != null) {
                identifier = asset.getIdentifierString();
            }
        }
        AssetResponse assetResponse = null;
        VPOA2MPService oa2MPService = (VPOA2MPService) getOA4MPService();

        UserInfo ui = null;
        if (identifier == null) {
            // Since this is a demo servlet, we don't blow up if there is no identifier found, just can't save anything.
            String msg = "Error: no cookie found. Cannot save certificates";
            warn(msg);
            debug("No cookie found");
            //if(asset == null) asset = new OA2Asset(BasicIdentifier.newID())
            ATResponse2 atResponse2 = oa2MPService.getAccessToken(asset, grant);
            ui = oa2MPService.getUserInfo(atResponse2.getAccessToken().toString());
            assetResponse = oa2MPService.getCert(asset, atResponse2);
        } else {
            asset = (VPOA2Asset) getCE().getAssetStore().get(identifier);
            if(asset.getState() == null || !asset.getState().equals(state)){
                warn("The expected state from the server was \"" + asset.getState() + "\", but instead \"" + state + "\" was returned. Transaction aborted.");
                throw new IllegalArgumentException("Error: The state returned by the server is invalid.");
            }
            ATResponse2 atResponse2 = oa2MPService.getAccessToken(asset, grant);
          //  ui = oa2MPService.getUserInfo(atResponse2.getAccessToken().getToken());
            ui = oa2MPService.getUserInfo(identifier);
            
            assetResponse = oa2MPService.getProxy(asset, atResponse2);

            // The general case is to do the call with the identifier if you want the asset store managed.
            //assetResponse = getOA4MPService().getCert(token, null, BasicIdentifier.newID(identifier));
        }
        // The work in this call

        // Again, we take the first returned cert to peel off some information to display. This
        // just proves we got a response.
        //X509Certificate cert = assetResponse.getX509Certificates()[0];
        byte[] proxy = ((ProxyAssetResponse)assetResponse).getProxy();

        info("2.b. Done! Displaying success page.");

        // Rest of this is putting up something for the user to see
        //request.setAttribute("certSubject", cert.getSubjectDN());
        //request.setAttribute("cert", CertUtil.toPEM(assetResponse.getX509Certificates()));
        request.setAttribute("cert", new String(proxy));
        request.setAttribute("username", assetResponse.getUsername());
        if(ui != null) {
            request.setAttribute("userinfo", ui.toJSon());
        }else{
            request.setAttribute("userinfo", "no user info returned.");

        }
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
