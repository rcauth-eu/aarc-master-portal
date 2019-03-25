package eu.rcauth.masterportal.client.servlet;

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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import eu.rcauth.masterportal.MPServerContext;
import eu.rcauth.masterportal.MPClientContext;
import eu.rcauth.masterportal.client.MPOA2Asset;
import eu.rcauth.masterportal.servlet.util.CookieUtils;

import java.net.URI;

/**
 * This servlet acts as a simple 'redirect_uri' for the Delegation Server. 
 * Just like the sample OA4MP Ready Servlet, this will also issue requests
 * to the /token and the /userinfo endpoints of the Delegation Server with 
 * using the received authorization grant. It does not, however, call 
 * the /getcert endpoint (this is done via {@link MPOA2ForwardingGetCertServer}.
 * <p> 
 * After successfully executing the /token and /userinfo requests this servlet
 * will forward the pending request to the MP Server with relevant information
 * about the authenticated user, such as:
 * <ul>
 * <li> The MP Server request code for identifying the MP Server session </li>
 * <li> The MP Server request state for identifying the MP Server session </li>  
 * <li> The username (subject) of the authenticated user </li>
 * <li> The claims received from the Delegation Server </li>
 * <li> An action parameter asserting the success of the authentication </li> 
 * </ul>
 * @author "Tamás Balogh"
 *
 */
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
        String identifier = CookieUtils.clearCookie(request, response, MPClientContext.MP_CLIENT_REQUEST_ID);
        
        
        MPOA2Asset asset = null;
        /*
        if (identifier == null) {
        	System.out.println("Getting Asset from token: " + token);
            asset = (MPOA2Asset) getCE().getAssetStore().getByToken(BasicIdentifier.newID(token));
            System.out.println("Getting Asset: " + asset);
            if (asset != null) {
                identifier = asset.getIdentifierString();
                System.out.println("Getting identifier: " + identifier);
            }
        }
        */
        
        AssetResponse assetResponse = null;
        UserInfo userInfo = null;
        OA2MPService oa2MPService = (OA2MPService) getOA4MPService();

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

            info("2.a Getting username from /userInfo");
            String userSubject = userInfo.getSub();
            
            // save username into asset! Without this the following /forwardGetCert call will not know what username
            // to store the returned certificate under in the MyProxy store.
            asset.setUsername(userSubject);
            getCE().getAssetStore().save(asset);
            
            
            String reqState = asset.getMPServerRequestState();
            String reqCode = asset.getMPServerRequestCode();
            
            info("2.a Returning to MP-Server with code : " + reqCode + " state : " + reqState + " and username: " + userSubject);
            
            // setting parameters for the MP Server. use Attributes for passing parameters since 
            // these are only transfered within the web container.
            
            request.setAttribute(MPServerContext.MP_SERVER_AUTHORIZE_CODE, reqCode);
            request.setAttribute(MPServerContext.MP_SERVER_AUTHORIZE_STATE, reqState);
            request.setAttribute(MPServerContext.MP_SERVER_AUTHORIZE_USERNAME, userSubject);
            request.setAttribute(MPServerContext.MP_SERVER_AUTHORIZE_CLAIMS, userInfo.toJSon().toString() );
            request.setAttribute(MPServerContext.MP_SERVER_AUTHORIZE_ACTION, MPServerContext.MP_SERVER_AUTHORIZE_ACTION_OK);
            
            // do the actual forwarding to the MP Server /authorize endpoint
            
            ServletContext serverContext = getServletConfig().getServletContext();
            ServletContext clientContext = serverContext.getContext(MPServerContext.MP_SERVER_CONTEXT);
             
            RequestDispatcher dispatcher = clientContext.getRequestDispatcher(MPServerContext.MP_SERVER_AUTHORIZE_ENDPOINT);
            dispatcher.forward(request, response);
            
        }
        
        return;
		
	}
	

	
}
