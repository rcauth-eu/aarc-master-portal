package eu.rcauth.masterportal.client.servlet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.servlet.ServiceClientHTTPException;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;
import eu.rcauth.masterportal.MPClientContext;

import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;

import static edu.uiuc.ncsa.security.core.util.DateUtils.checkTimestamp;

/**
 * This servlet implements the /forwardGetCert endpoint. This endpoint was introduced
 * as an internal endpoint and only meant to be called from the MP Server.
 * <p>
 * Calling this endpoint initiates a /getcert request issued to the Delegation Server.
 * Note that for this to work, you need to have a valid session identified by the
 * MPClientContext.MP_CLIENT_REQUEST_ID. On success, this endpoint will take care of storing
 * a Long Lived Proxy Certificate derived from the certificate returned from the
 * Delegation Server, and return a success code to the MP Server. No actual credential is
 * returned by this endpoint.
 *
 * @see <a href="https://wiki.nikhef.nl/grid/Master_Portal_Internals">wiki</a>
 *
 * @author "Tamás Balogh"
 *
 */
public class MPOA2ForwardingGetCertServer extends ClientServlet {

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {

        info("3.a Starting /getcert call to the Delegation Server");

        OA2MPService oa2MPService = (OA2MPService) getOA4MPService();

        // get the session identifier from the request
        String identifier = (String) request.getAttribute(MPClientContext.MP_CLIENT_REQUEST_ID);

        if (identifier == null) {

            String msg = "Identifier not found in cookies! Cannot get the transaction asset";
            // ServiceClientHTTPException is handled by OA2ClientExceptionHandler that parses
            // our JSON fields to put into the client-error.jsp and which are retrieved by
            // the MPOA2RequestForwarder running in the mp-server.
            ServiceClientHTTPException se = new ServiceClientHTTPException(msg);
            JSONObject jsonObj = new JSONObject();
            jsonObj.put("message", msg);
            jsonObj.put("error", "server_error");
            jsonObj.put("error_description", msg);
            se.setContent(jsonObj.toString());
            se.setStatus(HttpStatus.SC_INTERNAL_SERVER_ERROR);
            throw se;

        } else {

            info("3.a Received a session identifier : " + identifier);

            OA2Asset asset = (OA2Asset) getCE().getAssetStore().get(identifier);
            // NOTE: checking whether we still have a valid access token locally is much more efficient than
            // relying on the DS to return an error, as this saves us creating a keyPair and CSR plus setting
            // up an SSL connection. The disadvantage is that we rely on the lifetime being fixed using
            // edu.uiuc.ncsa.security.core.util.DateUtils.MAX_TIMEOUT also in the DS.
            if (asset.getRefreshToken()==null) {
                try {
                    checkTimestamp(asset.getAccessToken().getToken());
                } catch (InvalidTimestampException e) {
                    warn("Access token for CA is no valid: "+e.getMessage());
                    String msg = "CA Access token expired, cannot retrieve new EEC: "+e.getMessage();
                    ServiceClientHTTPException se = new ServiceClientHTTPException(msg);
                    // Put together a JSON content for the ServiceClientHTTPException whu
                    JSONObject jsonObj = new JSONObject();
                    // ServiceClientHTTPException is handled by OA2ClientExceptionHandler that parses
                    // our JSON fields to put into the client-error.jsp and which are retrieved by
                    // the MPOA2RequestForwarder running in the mp-server.
                    // Put longer message in message and shorter to-the-point in error_description.
                    jsonObj.put("message", msg);
                    jsonObj.put("error", "invalid_request");
                    jsonObj.put("error_description", "CA Access token expired, cannot retrieve new EEC");
                    se.setContent(jsonObj.toString());
                    se.setStatus(HttpStatus.SC_FORBIDDEN);
                    throw se;
                }
            }
            ATResponse2 atResponse2 = new ATResponse2(asset.getAccessToken(), asset.getRefreshToken());
            // Note: we don't actually use the returned AssetResponse
            oa2MPService.getCert(asset, atResponse2);

            info("3.c Successfuly completed /getcert call");

            // set status code, so the calling OA4MP Server will know that the call succeeded.
            response.setStatus(HttpStatus.SC_OK);
        }

    }

}
