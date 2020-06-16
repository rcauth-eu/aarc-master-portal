package eu.rcauth.masterportal.server.servlet;

import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.myproxy.MyProxyCredentialInfo;
import edu.uiuc.ncsa.myproxy.exception.MyProxyCertExpiredException;
import edu.uiuc.ncsa.myproxy.exception.MyProxyNoUserException;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ProxyServlet;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.server.request.PARequest;
import edu.uiuc.ncsa.security.delegation.server.request.PAResponse;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;

import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;

import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ATException;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.util.Map;

import java.security.KeyPair;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;
import org.apache.http.HttpStatus;

import eu.rcauth.masterportal.MPClientContext;
import eu.rcauth.masterportal.server.MPOA2RequestForwarder;
import eu.rcauth.masterportal.server.MPOA2SE;
import eu.rcauth.masterportal.server.MPOA2ServiceTransaction;
import eu.rcauth.masterportal.server.exception.InvalidDNException;
import eu.rcauth.masterportal.server.exception.InvalidRequestLifetimeException;
import eu.rcauth.masterportal.server.exception.ShortProxyLifetimeException;
import eu.rcauth.masterportal.server.validators.GetProxyRequestValidator;

/**
 * Class implementing the MasterPortal's version of a /getproxy endpoint
 * @see OA2ProxyServlet
 *
 * @author and Tam&aacute;s Balogh and Mischa Sall&eacute;
 */
public class MPOA2ProxyServlet extends OA2ProxyServlet {

    /** parameter name indicating this is a myproxy INFO request */
    public static final String INFOREQUEST = "info";
    /** claim name for the username in the INFO response */
    public static final String USERNAME = "username";
    /** claim name for the timeleft in the INFO response */
    public static final String TIMELEFT = "timeleft";
    /** claim name for the tolerance in the INFO response */
    public static final String TOLERANCE = "tolerance";

    /* OVERRIDDEN METHODS */

    /**
     * Overrides parent to distinguish between normal /getproxy and myproxy INFO request.
     * In case this is an {@link #INFOREQUEST} we call {@link #doMyproxyInfo(HttpServletRequest, HttpServletResponse)},
     * otherwise we just call our super's method.
     * @param httpServletRequest incoming /getproxy request
     * @param httpServletResponse outgoing response
     * @throws Throwable in case of errors
     */
    @Override
    protected void doDelegation(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        if (httpServletRequest.getParameterValues(INFOREQUEST) != null)
            doMyproxyInfo(httpServletRequest, httpServletResponse);
        else
            super.doDelegation(httpServletRequest, httpServletResponse);
    }

    /**
     *  Does two additional checks on top of those in {@link OA2ProxyServlet#verifyAndGet(IssuerResponse)}:
     *  whether this is a {@link #INFOREQUEST} and whether the request has a proxy lifetime value.
     *  If it has no proxy lifetime value, if will override the transaction default lifetime to a
     *  Master Portal specific default lifetime value. See the Master Portal Server cfg.xml for the
     *  default lifetime setting.
     *
     *  @param iResponse The response object being constructed
     *  @return The service transaction built for this session
     */
    @Override
    public MPOA2ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        MPOA2ServiceTransaction trans;
        try {
            trans = (MPOA2ServiceTransaction)super.verifyAndGet(iResponse);
        } catch (OA2GeneralError e) {
            throw new OA2ATException(e.getError(), e.getDescription(), e.getHttpStatus());
        }

        MPOA2SE se = (MPOA2SE) getServiceEnvironment();
        Map<String,String> params = iResponse.getParameters();

        if (!params.containsKey(OA2Constants.PROXY_LIFETIME)) {
            trans.setLifetime( 1000 * se.getMyproxyDefaultLifetime() );
            debug("6.a. Setting proxy lifetime to Master Portal Server default value = " + trans.getLifetime());
        }

        /* Store request type in the transaction such that we can retrieve it later in {@link #prepare} */
        trans.setIsInforequest(params.containsKey(INFOREQUEST));

        return trans;
    }

    /**
     *  Creates a MyProxy connection with the MyProxy password configured in the
     *  Master Portal Server cfg.xml.
     *
     *  @param st The current service transaction
     *  @throws GeneralSecurityException In case of unsuccessful connection
     */
    @Override
    protected void checkMPConnection(OA2ServiceTransaction st) throws GeneralSecurityException {
        if (!hasMPConnection(st)) {
            String myproxyPassword  = ((MPOA2SE)getServiceEnvironment()).getMyproxyPassword();
            debug("Creating new MP connection with username: " + st.getUsername() + " and lifetime: " + st.getLifetime());
            createMPConnection(st.getIdentifier(), st.getUsername(), myproxyPassword, st.getLifetime());
        }
    }

    /**
     *  Prepare for the upcoming /getproxy request. In order to assure that the
     *  MyProxy GET command will succeed, first this method will make sure that
     *  the MyProxy Credential Store has a valid proxy for the user, by
     *  executing a MyProxy INFO command first. If the results of the MyProxy
     *  INFO are unsatisfactory, this method will forward a /getcert request to
     *  the Delegation Server (via the Master Portal Client). Once that all
     *  succeeds, either a new proxy key+CSR is created or we return the myproxy
     *  INFO in case this is a {@link #INFOREQUEST}.
     *
     *  @param transaction The current service transaction
     *  @param request The original /getproxy request object
     *  @param response The response object for the /getproxy call
     *  @throws Throwable If general errors occur
     *
     */
    @Override
    protected void prepare(ServiceTransaction transaction, HttpServletRequest request, HttpServletResponse response) throws Throwable {
        super.prepare(transaction, request, response);

        MPOA2SE se = (MPOA2SE) getServiceEnvironment();
        MPOA2ServiceTransaction trans = (MPOA2ServiceTransaction)transaction;
        GetProxyRequestValidator[] validators = se.getValidators();

        // establish a myproxy connection so that we can execute an INFO command
        checkMPConnection(trans);
        MyProxyConnectable mpc = getMPConnection(trans);

        // track if we need to forward the request and obtain a new long-lived
        // proxy
        boolean validProxy = getMyproxyInfo(mpc, validators, trans, request, response);

        if (! validProxy) {
            info("2.a. Proxy retrieval failed! Asking for a new user certificate ...");
            // call /forwardgetcert on the Master Portal Client component
            forwardRealCertRequest(trans, request, response);
            if (trans.getIsInforequest()) {
                // For a myproxy info call we redo the myproxy INFO request
                if (! getMyproxyInfo(mpc, validators, trans, request, response)){
                    // Something is not right: we should have had a proxy by now
                    throw new OA2ATException(OA2Errors.SERVER_ERROR, "Could not get myproxy information", HttpStatus.SC_INTERNAL_SERVER_ERROR);
                }
                // all done, myproxy INFO is now in the transaction.
                return;
            }
        } else if (trans.getIsInforequest()) {
            // all done, myproxy INFO is now in the transaction.
            return;

        }

        // When we get here, we have either successfully forwarded or there is
        // a valid proxy in the myproxy store.
        debug("6.a. Generating keypair for proxy creation");
        // create keypair
        KeyPair keyPair = null;
        MyPKCS10CertRequest certReq = null;
        try {
            keyPair = KeyUtil.generateKeyPair();
            certReq = CertUtil.createCertRequest(keyPair, trans.getUsername());
        } catch (Throwable e) {
            if (e instanceof RuntimeException)
                throw e;
            warn("Could not create cert request: "+e.getMessage());
            throw new OA2ATException(OA2Errors.SERVER_ERROR, "Could not create cert request", HttpStatus.SC_INTERNAL_SERVER_ERROR);
        }

        // insert a CSR and generated keypair into the transaction
        trans.setCertReq(certReq);
        trans.setKeypair(keyPair);
    }

    /* HELPER METHODS */

    /**
     * Helper method doing a myproxy INFO call using the given mpc connector storing the result in the transaction.
     * Additionally, it also runs the list of GetProxyRequestValidator since some of these should
     * be run after each myproxy info request.
     * @param mpc MyProxy connection
     * @param validators list of validators that are run for the incoming request
     * @param trans MPOA2ServiceTransaction used among others to store the myproxy info in
     * @param request incoming /getproxy request
     * @param response outgoing response
     * @return boolean indicating whether we have myproxy info for a validated proxy certificate
     */
    protected boolean getMyproxyInfo(MyProxyConnectable mpc, GetProxyRequestValidator[] validators, MPOA2ServiceTransaction trans, HttpServletRequest request, HttpServletResponse response) {
        boolean validProxy = false;

        // Need to split the try-catch blocks into two: the validators are
        // expected to run AFTER the myproxy info call, but at that stage, we
        // still might need to fail on the input request parameters such as the
        // requested proxy lifetime. This is certainly not ideal, but we
        // currently have only one type of validator.
        MyProxyCredentialInfo mpc_info = null;
        try {
            // executing myproxy INFO
            info("Executing MyProxy INFO");
            mpc_info = mpc.doInfo();
            debug("Valid proxy certificate found!");
            // set flag to true for now, it might still change after running the
            // validators
            validProxy = true;

            debug("--- INFO ---");
            debug(mpc_info.toString());
            debug("--- INFO ---");

        } catch (MyProxyNoUserException e) {
            debug("No user found in MyProxy Credential Store!");
            debug(e.getMessage());
            validProxy = false;
        } catch (MyProxyCertExpiredException e) {
            debug("User certificate from MyProxy Credential Store is expired!");
            debug(e.getMessage());
            validProxy = false;
        } catch (Throwable e) {
            // myproxy info failed for some unknown reason: don't try to fix
            warn("myproxy info failed: " + e.getMessage());
            throw new OA2ATException(OA2Errors.SERVER_ERROR, "MyProxy info failed", HttpStatus.SC_INTERNAL_SERVER_ERROR);
        }

        try {
            // execute request validator in order. Note that some validators
            // will not do anything in case of empty mpc_info, but we should
            // still run the validators now, e.g. to test whether the requested
            // lifetime is more than the server maximum.
            for (GetProxyRequestValidator validator : validators) {
                validator.validate(trans, request, response, mpc_info);
            }
        } catch (ShortProxyLifetimeException e) {
            debug("The requested lifetime exceeds remaining proxy lifetime!");
            debug(e.getMessage());
            validProxy = false;
        } catch (InvalidDNException e) {
            debug("Invalid Proxy! The cached proxy DN does not match the DN returned by the Delegation Server!");
            debug(e.getMessage());
            validProxy = false;
        } catch (InvalidRequestLifetimeException e) {   // Fail on this one
            debug("The requested lifetime exceeds server maximum!");
            String mesg = e.getMessage();
            // don't request new certificate in this case, it's a user error
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, mesg, HttpStatus.SC_BAD_REQUEST);
        } catch (Throwable e) {
            warn("Validation of /getproxy request failed: " + e.getMessage());
            throw new OA2ATException(OA2Errors.SERVER_ERROR, "Validating of /getproxy request failed", HttpStatus.SC_BAD_REQUEST);
        }

        // Store the now valid myproxy info in the MPOA2ServiceTransaction
        trans.setMpcInfo(mpc_info);

        return validProxy;
    }

    /**
     * Forward the currently pending request to the Master Portal Client's
     * {@link MPClientContext#MP_CLIENT_FWGETCERT_ENDPOINT} endpoint.
     * This method should be called if a new certificate is needed in the Credential Store, since
     * this will set off a /getcert call to the Delegation Server.
     *
     * @param trans The current service transaction
     * @param request The original /getproxy request object
     * @param response The response of the /getproxy request
     * @throws Throwable In case of general errors.
     */
    protected void forwardRealCertRequest(ServiceTransaction trans, HttpServletRequest request, HttpServletResponse response) throws Throwable {
        info("Forwarding getCert request to Master Portal Client");

        // extract client session ID and send it along with the request for session keeping
        String clientID = ((MPOA2ServiceTransaction)trans).getMPClientSessionIdentifier();
        request.setAttribute(MPClientContext.MP_CLIENT_REQUEST_ID, clientID);

        // forward request to MP-Client
        ServletContext serverContext = getServletConfig().getServletContext();
        ServletContext clientContext = serverContext.getContext(MPClientContext.MP_CLIENT_CONTEXT);

        RequestDispatcher dispatcher = clientContext.getRequestDispatcher(MPClientContext.MP_CLIENT_FWGETCERT_ENDPOINT);
        // use include instead of forward here so that the responses returned to the requester will be aggregated
        // without this, the certificate will not be included into the response, since the response is already
        // written by the forwarding call.
        //dispatcher.include( request , response );

        // forwardRequest is used for front and backchannel forwarding, getproxy is backchannel
        MPOA2RequestForwarder.forwardRequest(request, response, dispatcher, true, false);

        info("Ended forwarding getCert to Master Portal Client");
    }

    /**
     * In case we have given an {@link #INFOREQUEST} parameter, we should return
     * a JSON containing the myproxy info instead of a proxy chain, this method
     * is then run instead of {@link #doDelegation(HttpServletRequest, HttpServletResponse)}.
     * @param httpServletRequest The original /getproxy request object
     * @param httpServletResponse response The response of the /getproxy request
     * @throws Throwable In case of general errors.
     */
    protected void doMyproxyInfo(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        info("6.a. Starting to process myproxy info request");
        PARequest paRequest = new PARequest(httpServletRequest, getClient(httpServletRequest));
        String statusString = "client = " + paRequest.getClient().getIdentifier();
        // The next call will pull the access token off of any parameters. The result may be null if there is
        // no access token.
        paRequest.setAccessToken(getAccessToken(httpServletRequest));

        PAResponse paResponse = (PAResponse) getPAI().process(paRequest);
        debug("6.a. " + statusString);
        MPOA2ServiceTransaction t = verifyAndGet(paResponse);

        // prepare does the real work, getting the myproxy info and possibly even a new long-lived proxy from the DS.
        prepare(t,httpServletRequest,httpServletResponse);

        // We should by now have the myproxy info in the MPOA2ServiceTransaction
        MyProxyCredentialInfo mpcInfo = t.getMpcInfo();

        // Not entirely sure whether we should save it but it seems using refreshed ATs
        // otherwise cannot find the transaction after a while.
        getTransactionStore().save(t);

        // Build-up the output JSON
        JSONObject json = new JSONObject();
        json.put(USERNAME, t.getUsername());
        // Note: getEndTime() returns milliseconds
        json.put(TIMELEFT, mpcInfo.getEndTime()/1000);
        long tolerance = t.getProxyLifetimeTolerance();
        // Only add valid tolerance
        if (tolerance >= 0)
            json.put(TOLERANCE, tolerance);

        info("6.b. Writing out MyProxy INFO for request " + statusString);
        // Convert to a pretty-printed String
        String content = JSONUtils.valueToString(json, 1, 0);

        // Now print the JSON
        httpServletResponse.setContentType("application/json");
        httpServletResponse.setCharacterEncoding("UTF-8");
        httpServletResponse.setContentLength(content.length());
        PrintWriter printWriter = httpServletResponse.getWriter();

        printWriter.write(content);
        printWriter.flush();
        printWriter.close();

        info("6.b. Completed transaction " + t.getIdentifierString() + ", " + statusString);
    }

}
