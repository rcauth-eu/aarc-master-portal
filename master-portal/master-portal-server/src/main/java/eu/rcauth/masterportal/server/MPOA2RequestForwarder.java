package eu.rcauth.masterportal.server;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;
import org.apache.http.HttpStatus;
import eu.rcauth.masterportal.servlet.util.ContentAwareHttpServletResponse;

import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;

public class MPOA2RequestForwarder {

    /**
     *  Forward requests to another endpoint. This method is used by the OA4MP-Server to forward
     *  calls to the OA4MP-Client. This method abstract error handling based on returned status
     *  codes.
     *
     *  @param request The original request object being forwarded
     *  @param response The original response object
     *  @param dispatcher The request dispatcher taking care of switching contexts
     *  @param aggregateResponse Decides whether to aggregate the response coming from the forwarding
     *  with the original response object or not.
     *
     *  @throws Throwable for general errors
     */
    public static void forwardRequest(HttpServletRequest request,
                                      HttpServletResponse response,
                                      RequestDispatcher dispatcher,
                                      boolean aggregateResponse)  throws Throwable {

        ContentAwareHttpServletResponse responseWrapper = new ContentAwareHttpServletResponse(response);

        if (aggregateResponse) {
            dispatcher.include(request , responseWrapper );
        } else {
            dispatcher.forward(request, responseWrapper );
        }

        // everything other than OK will trigger an exception in the OA4MP Server.
        // Note: for newer versions of Tomcat, we can call getStatus() on a HttpServletResponseWrapper.
        // We need to make sure it's called getStatus() in order to always call the correct one.
        int status=responseWrapper.getStatus();
        if (status != HttpStatus.SC_OK) {
            String mesg;
            String logerr="";
            if (status == HttpStatus.SC_NO_CONTENT)
                mesg="Master Portal (OA4MP Client) returned an empty response";
            else {
                mesg = "Master Portal (OA4MP Client) returned with unexpected HTTP Status " + status;
                logerr = "mp-client returned: " + responseWrapper.getRawResponse();
            }

            // Note: error in authentication request in OIDC and OAuth2 need to be send to redirect_uri
            String redirect_uri = null;
            String state = null;
            try {
                redirect_uri = request.getParameter(OA2Constants.REDIRECT_URI);
                state = request.getParameter(OA2Constants.STATE);
            } catch(Throwable e)  {
                // Ignore if we cannot retrieve either REDIRECT_URI or STATE
            }
            // Send to the redirect_uri if we have one, otherwise little choice but to throw a OA2GeneralError
            // NOTE the redirect_uri has already been verified (as required by the spec) before we even come here,
            // namely in OA2AuthorizationServer.doIt() in init.doDelegation(), while we are called via
            // MPOA2AuthorizationServer.present(), which is called at the end of doIt() in AbstractAuthorizationServlet.
            if (redirect_uri!=null)
                throw new OA2RedirectableError(OA2Errors.SERVER_ERROR, mesg, state, redirect_uri);
            else
                throw new OA2GeneralError(logerr, OA2Errors.SERVER_ERROR, mesg, HttpStatus.SC_INTERNAL_SERVER_ERROR);
        }

    }

}
