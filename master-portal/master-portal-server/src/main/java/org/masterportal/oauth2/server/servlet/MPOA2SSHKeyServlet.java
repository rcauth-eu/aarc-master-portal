package org.masterportal.oauth2.server.servlet;

import org.masterportal.oauth2.server.MPOA2SE;

import org.masterportal.oauth2.server.storage.SSHKey;
import org.masterportal.oauth2.server.storage.sql.SQLSSHKeyStore;

import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ExceptionHandler;

import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Utilities;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys.CONSUMER_KEY;
import static edu.uiuc.ncsa.security.core.util.DateUtils.checkTimestamp;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.CLIENT_SECRET;

import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.net.URI;
import java.io.Writer;
import java.io.IOException;
import java.util.List;
import java.util.Collections;
import java.util.Base64;


/**
 * <p>Created by Mischa Sall&eacute;<br>
 * Main SSH public Key API servlet for uploading SSH pulbic keys to the Master
 * Portal. The resulting list can be obtained via the {@link
 * MPOA2SSHKeyListingServlet} servlet.
 * @see MPOA2SSHKeyListingServlet
 */
public class MPOA2SSHKeyServlet extends MyProxyDelegationServlet {
    // Valid request parameters
    private static final String ACTION_PARAMETER = "action";
    private static final String LABEL_PARAMETER = "label";
    private static final String PUBKEY_PARAMETER = "pubkey";
    private static final String DESCRIPTION_PARAMETER = "description";

    // Valid actions
    private static final String ACTION_ADD	= "add";
    private static final String ACTION_UPDATE	= "update";
    private static final String ACTION_REMOVE	= "remove";
    private static final String ACTION_GET	= "get";
    private static final String ACTION_LIST	= "list";

    // SSH public key's first field should start with the following
    private static final String SSH_KEY_START = "ssh-";
    // default labels start with prefix followed by a serial
    private static final String LABEL_PREFIX="ssh-key-";


    private MPOA2SE se;
    private MyLoggingFacade logger;

    @Override
    public void init() throws ServletException	{
	super.init();
	se = (MPOA2SE)getServiceEnvironment();
	setEnvironment(se);

	// Create custom logger for exceptions and the like
//	logger = new MyLoggingFacade(getClass().getSimpleName(), false);
	logger = getMyLogger();
	setExceptionHandler(new OA2ExceptionHandler(logger));
    }

    /**
     * Servlet does not implement/use verifyAndGet
     */
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
	return null;
    }

    /**
     * Copy and paste from {@link OA2CertServlet}, except we allow here an
     * absent client.
     */
    @Override
    public Client getClient(HttpServletRequest req) {
        String rawID = req.getParameter(CONST(CONSUMER_KEY));
        String rawSecret = getFirstParameterValue(req, CLIENT_SECRET);
        // According to the spec. this must be in anBasic Authz header if it is not sent as parameter
        List<String> basicTokens = getAuthHeader(req, "Basic");
        if (2 < basicTokens.size()) {
            // too many tokens to unscramble
            throw new OA2GeneralError(OA2Errors.INVALID_TOKEN,
		    "Error: Too many authorization tokens.",
		    HttpStatus.SC_FORBIDDEN);
        }
        if (rawID == null) {
            // maybe it was sent as an authorization header
            // now we have to check for which of these is the identifier

            for (String x : basicTokens) {
                try {
                    // Here is some detective work. We get up to TWO basic Authz headers with the id and secret.
                    // Since ids are valid URIs the idea here is anything that is uri must be an id and the other
                    // one is the secret. This also handles the case that one of these is sent as a parameter
                    // in the call and the other is in the header.
                    URI test = URI.create(x);
                    // It is possible that the secret may be parseable as a valid URI (plain strings are
                    // trivially uris). This checks that there a
                    // scheme, which implies this is an id. The other token is assumed to
                    // be the secret.
                    if (test.getScheme() != null) {
                        rawID = x;
                    } else {
                        rawSecret = x;
                    }
                } catch (Throwable t) {
                    if (rawSecret == null) {
                        rawSecret = x;
                    }
                }
            }
        }
        if (rawID == null) {
	    // no client_id
            return null;
        }
        Identifier id = BasicIdentifier.newID(rawID);
        OA2Client client = (OA2Client) getClient(id);

        if (rawSecret == null) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "Error: No secret. request refused.",
                    HttpStatus.SC_BAD_REQUEST);
        }
        if (!client.getSecret().equals(DigestUtils.shaHex(rawSecret))) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "Error: Secret is incorrect. request refused.",
                    HttpStatus.SC_FORBIDDEN);

        }
        return client;
    }

    @Override
    protected void handleException(Throwable t, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
	// ok, if it is a strange error, print a stack if you need to.
	// Note: getMyLogger gives logger from environment, which is configured
	// via conf file and logs typically into mp server logs, not in
	// /var/log/messages
        if (logger.isDebugOn()) {
            t.printStackTrace();
        }
	getExceptionHandler().handleException(t, request, response);
    }

    /**
     * main method doing all the handling of the API requests
     */
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
	// Get transaction for this request, based on access_token
	ServiceTransaction transaction = getAndVerifyTransaction(request);

	// Get the client_id: for ADD and DELETE this is mandatory, for the
	// others: if present it should be valid and match the access_token
	Client client = getClient(request);
	if (client!=null) {
	    if (! transaction.getClient().equals(client)) {
		throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "client_id does not match access token.", HttpStatus.SC_BAD_REQUEST);
	    }
	    checkClient(client);
	}

	// Get username from transaction
	String userName=transaction.getUsername();

	// Get parameters from request: they will be null if absent
	String action = null;
	String label = null;
	String pubKey = null;
	String description = null;
	try {
	    action = OA2Utilities.getParam(request, ACTION_PARAMETER);
	    label = OA2Utilities.getParam(request, LABEL_PARAMETER);
	    pubKey = OA2Utilities.getParam(request, PUBKEY_PARAMETER);
	    description = OA2Utilities.getParam(request, DESCRIPTION_PARAMETER);
	} catch (OA2RedirectableError e)	{
	    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, e.getDescription(), HttpStatus.SC_BAD_REQUEST);
	}

	// action must be present
	if (action==null)	{
	    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
				      "Missing mandatory action parameter",
				      HttpStatus.SC_BAD_REQUEST);
	}
	
	switch (action) {
	    case ACTION_ADD :
		// For adding client is mandatory
		if (client==null)   {
		    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
					      "Missing client for action "+action,
					      HttpStatus.SC_BAD_REQUEST);
		}
		addKey(userName, label, pubKey, description);
		break;
	    case ACTION_UPDATE :
		// For adding client is mandatory
		if (client==null)   {
		    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
					      "Missing client for action "+action,
					      HttpStatus.SC_BAD_REQUEST);
		}
		updateKey(userName, label, pubKey, description);
		break;
	    case ACTION_REMOVE :
		removeKey(userName, label);
		break;
	    case ACTION_GET :
		SSHKey key = getKey(userName, label);
		writeKeys(response, Collections.singletonList(key));
		break;
	    case ACTION_LIST :
		writeKeys(response, getKeys(userName));
		break;
	    default:
		throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
					  "Invalid action specified: "+action,
					  HttpStatus.SC_BAD_REQUEST);
	}
    }

    /************************************************************************
     * API Action methods
     ************************************************************************/

    /**
     * Adds new key for given userName, label, pubKey and description.
     */
    private void addKey(String userName, String label, String pubKey, String description) throws Throwable {
	// userName and pubKey may not be empty, userName is indirect, via the
	// access_token
	if (userName==null || userName.isEmpty())   {
	    logger.error("Username is null or empty");
	    throw new GeneralException("Cannot get username");
	}
	if (pubKey==null || pubKey.isEmpty()) {
	    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "Missing mandatory pubkey", HttpStatus.SC_BAD_REQUEST);
	}

	// do (basic) sanity check on pubKey
	if (!isSSHPubKey(pubKey)) {
	    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "Pubkey does not look like a SSH public key", HttpStatus.SC_BAD_REQUEST);
	}

	// try to get store
	SQLSSHKeyStore store = (SQLSSHKeyStore)se.getSSHKeyStore();
	if ( store == null) {
	    logger.error("Cannot get SSHKeyStore");
	    throw new GeneralException("Could not get SSH KeyStore"); 
	}

	// Create new SSHKey object
	SSHKey key = new SSHKey(userName, label, pubKey, description);

	// Check whether the ssh pubKey already occurs: must be globally unique
	if ( store.containsKey(key) )  {
	    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "SSH Pubkey is already registered", HttpStatus.SC_BAD_REQUEST);
	}

	// Get existing keys: we need them either for counting or for creating
	// the next label
	List<SSHKey> currKeys = store.getAll(userName);

	// Check we don't have too many
	int maxSSHKeys = se.getMaxSSHKeys();
	if (maxSSHKeys > 0 && currKeys.size() >= maxSSHKeys)    {
	    logger.info("Maximum number of keys reached for user "+userName);
	    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "Maximum number of keys >= "+maxSSHKeys+", cannot add more", HttpStatus.SC_BAD_REQUEST);
	}

	// when label isn't set, create one
	if (label==null || label.isEmpty()) {
	    key.setLabel(createLabel(userName, currKeys));
	}

	// Now save the new key
	try {
	    store.register(key);
	} catch (Exception e)	{
	    Throwable cause = e.getCause();
	    if (cause == null)
		logger.error("Cannot register key: "+e.getMessage());
	    else
		logger.error("Cannot register key: "+e.getMessage() + " (" + cause.getMessage() + ")");
	    throw new OA2GeneralError(OA2Errors.SERVER_ERROR, "Cannot add entry", HttpStatus.SC_INTERNAL_SERVER_ERROR);
	}
    }

    /**
     * Update entry (pubKey and/or description) for given user, label.
     */
    private void updateKey(String userName, String label, String pubKey, String description) throws Throwable {
	// userName and label may not be empty
	if (userName==null || userName.isEmpty())   {
	    logger.error("Username is null or empty");
	    throw new GeneralException("Cannot get username");
	}
	if (label==null || label.isEmpty()) {
	    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "Missing mandatory label", HttpStatus.SC_BAD_REQUEST);
	}

	// if we specified a pubkey, it must be non-empty and valid
	if (pubKey!=null)	{
	    if (pubKey.isEmpty())	{
		throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "SSH public key may not be empty", HttpStatus.SC_BAD_REQUEST);
	    }
	    if (!isSSHPubKey(pubKey)) {
		throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "key does not look like a SSH public key", HttpStatus.SC_BAD_REQUEST);
	    }
	}

	// try to get store
	SQLSSHKeyStore store = (SQLSSHKeyStore)se.getSSHKeyStore();
	if ( store == null) {
	    logger.error("Cannot get SSHKeyStore");
	    throw new GeneralException("Could not get SSH KeyStore"); 
	}
    
	// Get existing pubkey
	SSHKey value = store.get(new SSHKey(userName, label));
	if (value==null) {
	    throw new OA2GeneralError("not_found", "No key to update found", HttpStatus.SC_NOT_FOUND);
	}

	// Update values
	if (pubKey != null)    {
	    info("Updating pubkey for key");
	    value.setPubKey(pubKey);
	}
	if (description != null)    {
	    info("Updating description for key");
	    value.setDescription(description);
	}

	// Update the value in the store
	try {
	    info("Updating the entry for "+userName+", "+label);
	    store.update(value);
	} catch (Exception e)	{
	    Throwable cause = e.getCause();
	    if (cause == null)
		logger.error("Cannot update key: "+e.getMessage());
	    else
		logger.error("Cannot update key: "+e.getMessage() + " (" + cause.getMessage() + ")");
	    throw new OA2GeneralError(OA2Errors.SERVER_ERROR, "Cannot update entry", HttpStatus.SC_INTERNAL_SERVER_ERROR);
	}
    }

    /**
     * Removes entry for given userName and label
     */
    private void removeKey(String userName, String label) throws Throwable {
	// userName and label may not be empty
	if (userName==null || userName.isEmpty())   {
	    logger.error("Username is null or empty");
	    throw new GeneralException("Cannot get username");
	}
	if (label==null || label.isEmpty()) {
	    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "Missing mandatory label", HttpStatus.SC_BAD_REQUEST);
	}

	// try to get store
	SQLSSHKeyStore store = (SQLSSHKeyStore)se.getSSHKeyStore();
	if ( store == null) {
	    logger.error("Cannot get SSHKeyStore");
	    throw new GeneralException("Could not get SSHKeyStore"); 
	}

	SSHKey key = null;
	try {
	    key = store.remove(new SSHKey(userName, label));
	} catch (Exception e)	{
	    Throwable cause = e.getCause();
	    if (cause == null)
		logger.error("Cannot remove key: "+e.getMessage());
	    else
		logger.error("Cannot remove key: "+e.getMessage() + " (" + cause.getMessage() + ")");
	    throw new OA2GeneralError(OA2Errors.SERVER_ERROR, "Cannot remove key", HttpStatus.SC_INTERNAL_SERVER_ERROR);
	}
	if (key==null) {
	    throw new OA2GeneralError("not_found", "No key found", HttpStatus.SC_NOT_FOUND);
	}
    }

    /**
     * Retrieves entry for given userName, label
     */
    private SSHKey getKey(String userName, String label) throws Throwable {
	// userName and label may not be empty
	if (userName==null || userName.isEmpty())   {
	    logger.error("Username is null or empty");
	    throw new GeneralException("Cannot get username");
	}
	if (label==null || label.isEmpty()) {
	    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "Missing mandatory label", HttpStatus.SC_BAD_REQUEST);
	}

	// try to get store
	SQLSSHKeyStore store = (SQLSSHKeyStore)se.getSSHKeyStore();
	if ( store == null) {
	    throw new GeneralException("Could not get SSH KeyStore"); 
	}

	SSHKey key = null;
	try {
	    key = store.get(new SSHKey(userName, label));
	} catch (Exception e)	{
	    Throwable cause = e.getCause();
	    if (cause == null)
		logger.error("Cannot get key: "+e.getMessage());
	    else
		logger.error("Cannot get key: "+e.getMessage() + " (" + cause.getMessage() + ")");
	    throw new OA2GeneralError(OA2Errors.SERVER_ERROR, "Cannot get key", HttpStatus.SC_INTERNAL_SERVER_ERROR);
	}
	if (key==null) {
	    throw new OA2GeneralError("not_found", "No key found", HttpStatus.SC_NOT_FOUND);
	}
    
	return key;
    }

    /**
     * lists all entries for given userName
     */
    private List<SSHKey> getKeys(String userName) throws Throwable  {
	// userName may not be empty
	if (userName==null || userName.isEmpty()) {
	    logger.error("Username is empty");
	    throw new GeneralException("Cannot get username");
	}

	// try to get store
	SQLSSHKeyStore store = (SQLSSHKeyStore)se.getSSHKeyStore();
	if ( store == null) {
	    throw new GeneralException("Could not get SSH KeyStore"); 
	}

	return store.getAll(userName);
    }

    /************************************************************************
     * Helper methods
     ************************************************************************/

    /**
     * Get access token from request, copy and paste from userinfo endpoint
     * {@link UserInfoServlet#doIt}
     */
    private ServiceTransaction getAndVerifyTransaction(HttpServletRequest request) {
	// Get access token: either bearer token or request parameter
        AccessToken at = null;
        List<String> authHeaders = getAuthHeader(request, "Bearer");

        if(authHeaders.isEmpty()){
            // it's not in a header, but was sent as a standard parameter.
            at = se.getTokenForge().getAccessToken(request);
        }else {
            // only the very first one is taken. Don't try to snoop for them.
            at = se.getTokenForge().getAccessToken(authHeaders.get(0));
        }
        if (at == null) {
            // the bearer token should be sent in the authorization header.
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "no access token was sent.", HttpStatus.SC_BAD_REQUEST);
        }

	// Is it still valid
	try {
            checkTimestamp(at.getToken());
        }catch(InvalidTimestampException itx){
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "token expired.", HttpStatus.SC_BAD_REQUEST);
        }catch(NumberFormatException nfx)   {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "invalid access token.", HttpStatus.SC_BAD_REQUEST);
	}

	// Now get the corresponding transaction and verify it's ok
        ServiceTransaction transaction = null;
	try {
	    transaction = (ServiceTransaction) getTransactionStore().get(at);
	} catch (Exception e)	{
            logger.error("Error: Cannot get transaction for access_token: "+e.getMessage());
            throw new GeneralException("Cannot get transaction for access_token");
	}
        if (transaction == null) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "no transaction for the access token was found.", HttpStatus.SC_BAD_REQUEST);
        }
        if (!transaction.isAccessTokenValid()) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "invalid access token.", HttpStatus.SC_BAD_REQUEST);
        }

        return transaction;
    }

    /**
     * Returns new unique label for userName, based on existing set of keys
     */
    private String createLabel(String userName, List<SSHKey> currKeys)	{
	if (currKeys!=null) {
	    // Loop backwards over keys until we find matching ssh-key-[0-9]\+
	    for (int i=currKeys.size()-1; i>=0 ; i--) {
		String label=currKeys.get(i).getLabel();
		if (label.matches(LABEL_PREFIX+"[0-9]+"))    {
		    // Found the last one, now get the suffix, add one and
		    // create the new label
		    int newSerial=1+Integer.parseInt(label.substring(LABEL_PREFIX.length()));
		    return LABEL_PREFIX+Integer.toString(newSerial);
		}
	    }
	}

	// No matches, will use new default
	return LABEL_PREFIX+"1";
    }


    /**
     * Writes JSON-formatted array of given List of keys to the response.
     */
    private void writeKeys(HttpServletResponse response, List<SSHKey> keys)    {
	JSONObject json = new JSONObject();
	for (SSHKey key : keys)	{
	    JSONObject jsonKey = new JSONObject();
	    jsonKey.put("label", key.getLabel());
	    jsonKey.put("username", key.getUserName());
	    jsonKey.put("pub_key", key.getPubKey());
	    if (key.getDescription() != null)
		jsonKey.put("description", key.getDescription());
	    json.accumulate("ssh_keys", jsonKey);
	}

	String out = JSONUtils.valueToString(json, 1, 0);
	response.setHeader("Content-Type", "application/json;charset=UTF-8");
	try {
	    Writer writer = response.getWriter();
	    writer.write(out);
	    writer.append('\n');
	    writer.close();
	    writer.flush();
	} catch(IOException e)	{
	    logger.error("Error: Cannot write keys: "+e.getMessage());
	    throw new GeneralException("Cannot write keys");
	}
    }

    /**
     * Does a basic sanity check on String key, whether it looks like an SSH
     * public key.
     */
    private boolean isSSHPubKey(String key) {
	int firstSpace=key.indexOf(' ');
	if (firstSpace<0)   {
	    logger.warn("Uploaded key does not contain a space");
	    return false;
	}

	// Get type part: must start with ssh-
	String type=key.substring(0, firstSpace);
	if (! type.substring(0,4).equals(SSH_KEY_START))   {
	    logger.warn("Uploaded key does not start with \""+SSH_KEY_START+"\"");
	    return false;
	}

	// Get encoded part
	int secondSpace=key.indexOf(' ', firstSpace+1);
	String encoded;
	if (secondSpace<0)  {
	    encoded=key.substring(firstSpace+1);
	} else	{
	    encoded=key.substring(firstSpace+1,secondSpace);
	}
	try {
	    byte[] decoded=Base64.getDecoder().decode(encoded);
	} catch(IllegalArgumentException e) {
	    logger.warn("Uploaded key does not contain base64-encoded part");
	    return false;
	}
	return true;
    }


}
