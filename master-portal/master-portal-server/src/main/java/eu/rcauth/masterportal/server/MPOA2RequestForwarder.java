package eu.rcauth.masterportal.server;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.http.HttpStatus;
import eu.rcauth.masterportal.servlet.util.ContentAwareHttpServletResponse;

import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ATException;

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
                                      boolean aggregateResponse,
                                      boolean frontChannel)  throws Throwable {

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
            String error;
            String error_description = null;
            // Set error string: for 4XX range, use invalid_request, anything else is a server_error
            if (400 <= status && status < 500) {
                error = OA2Errors.INVALID_REQUEST;
                // For 4XX range we can reprint either Error description or Message from the received client-error.jsp page.
                try {
                    JSON rawJSON = JSONSerializer.toJSON(responseWrapper.getRawResponse().trim());
                    if ((rawJSON instanceof JSONObject)) {
                        JSONObject jsonResponse = (JSONObject) rawJSON;
                        // First try error_description
                        Object msg = jsonResponse.get("error_description");
                        if (msg == null)
                            // Failover to message
                            msg = jsonResponse.get("message");
                        if (msg != null)
                            error_description = "Master Portal could not retrieve new EEC from CA: " + msg.toString();
                    }
                } catch (Exception e) {
                    // ignore failed JSON parsing
                }
            } else {
                error = OA2Errors.SERVER_ERROR;
                if (status == HttpStatus.SC_NO_CONTENT)
                    error_description = "Master Portal received empty response from CA";
            }

            // Use default if we have not description yet
            if (error_description == null)
                error_description = "Master Portal could not retrieve new EEC from CA, HTTP status code is "+status;

            // NOTE: Type of exception must be dependent on whether front- or backchannel.
            // In authentication request in OIDC and OAuth2 (=frontchannel) it needs to be send to
            // the redirect_uri when available, while backchannel should be JSON formatted.
            if (frontChannel) {
                // frontchannel: typically the /authorize. Should produce a HTML page, preferably redirected.
                String redirect_uri = null;
                String state = null;
                try {
                    redirect_uri = request.getParameter(OA2Constants.REDIRECT_URI);
                    state = request.getParameter(OA2Constants.STATE);
                } catch (Throwable e) {
                    // Ignore if we cannot retrieve either REDIRECT_URI or STATE
                }
                // Send to the redirect_uri if we have one, otherwise little choice but to throw a OA2GeneralError
                // NOTE the redirect_uri has already been verified (as required by the spec) before we even come here,
                // namely in OA2AuthorizationServer.doIt() in init.doDelegation(), while we are called via
                // MPOA2AuthorizationServer.present(), which is called at the end of doIt() in AbstractAuthorizationServlet.
                if (redirect_uri != null) {
                    throw new OA2RedirectableError(error, error_description, state, redirect_uri);
                } else {
                    String logerr = "mp-client returned: " + responseWrapper.getRawResponse();
                    throw new OA2GeneralError(logerr, error, error_description, status);
                }
            } else {
                // backchannel: typically the /getproxy. Should produce a JWT, not really a human-readable page.
                // Reuse the status code that was received by the mp-client and has been forwarded to us.
                // Note that we can get e.g. a ServiceClientHTTPException with status code 403 in case we're using
                // refresh tokens and the long-lived proxy has expired. In such a case we like to see a proper message
                // not a 500 Internal Server Error
                throw new OA2ATException(error, error_description, status);
            }
        }

    }

}
