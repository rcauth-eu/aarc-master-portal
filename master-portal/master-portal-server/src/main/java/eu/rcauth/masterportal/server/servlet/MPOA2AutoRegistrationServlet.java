package eu.rcauth.masterportal.server.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractRegistrationServlet;
import eu.rcauth.masterportal.server.MPOA2SE;

import edu.uiuc.ncsa.security.servlet.PresentableState;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2RegistrationServlet;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpStatus;

import java.net.URLEncoder;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import java.io.IOException;

public class MPOA2AutoRegistrationServlet extends OA2RegistrationServlet {
    /** Template shown when autoregistration succeeds */
    public static final String OK_PAGE = "/autoregistration-ok.jsp";
    /** Template shown when autoregistration fails */
    public static final String ERROR_PAGE = "/autoregistration-error.jsp";

    /** Basic 'approver' string set for auto-approved requests */
    public static final String APPROVER = "auto-approver";

    /** Request parameter to add an extra approver ID to the APPROVER */
    public static final String APPROVERID = "approverid";

    /** Valid regexp pattern for values of APPROVERID */
    public static final String APPROVERID_PATTERN = "[\\w\\-.~!*'();:@&=+$,/?%#\\[\\]]+";

    /**
     * We only use the {@link #REQUEST_STATE}, since we don't present a HTML
     * form but use a POST API call.
     *
     * @param request not used
     */
    @Override
    public int getState(HttpServletRequest request) {
        // Only REQUEST_STATE is supported
        return REQUEST_STATE;
    }


    /**
     * Override AbstractRegistrationServlet.handleError() since we should
     * present the OIDC error as JSON, not as an HTML page.
     *
     * @param state used for getting the request and response
     * @param t used for obtaining the error description
     */
    @Override
    public void handleError(PresentableState state, Throwable t) throws IOException, ServletException {
        // We need to produce a json page in case of error
        HttpServletRequest request = state.getRequest();
        HttpServletResponse response = state.getResponse();

        // Set the error parameter for the request, the error_description comes
        // from t.getMessage()
        request.setAttribute("error", "invalid_request");
        response.setStatus(HttpStatus.SC_BAD_REQUEST);
        // TODO: Might not be needed, perhaps need other headers
        response.setHeader("X-Frame-Options", "DENY");
        JSPUtil.handleException(t, request, response, ERROR_PAGE);
    }


    /**
     * Only checks whether the autoregistration endpoint is enabled in the
     * configuration, throws {@link ServletException} in case it isn't.
     *
     * @param state not used
     * @throws ServletException when the autoregistration endpoint is not enabled
     */
    @Override
    public void prepare(PresentableState state) throws Throwable {
        // Check whether the endpoint is enabled in the config
        if ( ! ((MPOA2SE)getServiceEnvironment()).getAutoRegisterEndpoint() )  {
            throw new ServletException("autoregistration endpoint is not enabled");
        }
        // Override to make it a NO-OP: we don't use a HTML page,
        // just a POST call
    }

    /**
     * Unfortunately we cannot rely on the parent version, since we need a
     * different OK_PAGE (not the one set and used in {@link
     * AbstractRegistrationServlet})
     *
     * @param state {@link edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractRegistrationServlet.ClientState} to get the Client from.
     * @throws Throwable in case of errors
     */
    @Override
    public void present(PresentableState state) throws Throwable {
        // First part is copy&paste from AbstractRegistrationServlet
        // Note that we only support REQUEST_STATE
        if (state instanceof ClientState) {
            ClientState cState = (ClientState) state;
            BaseClient client = cState.getClient();
            // Make the client object available for the OK_PAGE
            state.getRequest().setAttribute("client", client);
            JSPUtil.fwd(state.getRequest(), state.getResponse(), OK_PAGE);

            // Next part is from OA2RegistrationServlet

            // we should not store the client secret in the database, just a hash of it.
            String secret = DigestUtils.sha1Hex(client.getSecret());
            client.setSecret(secret);
            getServiceEnvironment().getClientStore().save((Client)client);
        } else {
            throw new IllegalStateException("Error: An instance of ClientState was expected, but got an instance of \"" + state.getClass().getName() + "\"");
        }
    }


    /**
     * Auto-registers a new client, should <B><I>ONLY</I></B> be used behind a
     * proxy, verifying the request (e.g. via OIDC federation).
     *
     * @param request contains the parameters for the new client
     * @param response the HttpResponse
     * @param fireClientEvents whether to call {@link AbstractRegistrationServlet#fireNewClientEvent(Client)}
     * @throws Throwable in case of errors
     */
    @Override
    protected Client addNewClient(HttpServletRequest request, HttpServletResponse response, boolean fireClientEvents) throws Throwable {
        Client client = null;
        // Make sure to catch ClientRegistrationRetryException since that would
        // be otherwise caught by AbstractRegistrationServlet.doIt() and a retry
        // page would be shown while we need to produce a OIDC JSON error page
        try {
            client = super.addNewClient(request, response, fireClientEvents);
        } catch (ClientRegistrationRetryException cRE) {
            // Need to remove the client
            removeClient(cRE.getClient());
            // Now throw a new exception
            throw new ServletException(cRE.getMessage());
        }

        // Form the correct approver string
        String approver= getApprover(request, client);

        // Approve the client
        approve(client, approver);

        return client;
    }


    /**
     * remove a previously registered client
     */
    private void removeClient(BaseClient client) {
        Identifier client_id = client.getIdentifier();
        info("Removing client, client="+client_id.toString());
        getServiceEnvironment().getClientStore().remove(client_id);
    }

    /**
     * returns the approver String for given client, depending on whether the
     * request contains a {@link #APPROVERID} parameter
     *
     * @param request used to get the {@link #APPROVERID} parameter.
     * @param client in case of error the {@link Client} is removed again.
     * @throws ServletException in case of errors
     */
    private String getApprover(HttpServletRequest request, Client client) throws ServletException {
        // Form the correct approver string
        String approver = null;

        String approverid = request.getParameter(APPROVERID);
        if (approverid == null) {
            // No approverid parameter found
            approver = APPROVER;
        } else {
            // Check validity of passed approverid value
            if (! approverid.matches(APPROVERID_PATTERN))  {
                warn("Invalid approverid \"" + approverid + "\"");
                // Need to remove the client
                removeClient(client);
                throw new ServletException("Invalid character in approverid parameter");
            }
            try {
                approver = APPROVER + ":" + URLEncoder.encode(approverid, "UTF-8");
            } catch (Exception e)   {
                throw new ServletException(e.getMessage());
            }
        }
        return approver;
    }


    /**
     * approves given client, using specified approver as the approver String
     *
     * @param client Client being approved
     * @param approver Approver of this client
     */
    private void approve(Client client, String approver)    {
        Identifier clientIdentifier = client.getIdentifier();
        // Get client approval store
        ClientApprovalStore<ClientApproval> clientApprovalStore = getServiceEnvironment().getClientApprovalStore();
        // create new client approval
        ClientApproval clientApproval = clientApprovalStore.create();

        // Set values
        clientApproval.setIdentifier(clientIdentifier);
        clientApproval.setApprover(approver);
        clientApproval.setApproved(true);
        // save new approval record
        clientApprovalStore.save(clientApproval);
        // Log the approval
        info("Auto-approving client="+clientIdentifier.toString());
    }
}
