package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import org.masterportal.oauth2.server.storage.SSHKey;
import org.masterportal.oauth2.server.storage.SSHKeyIdentifier;
import org.masterportal.oauth2.server.storage.sql.SQLSSHKeyStore;

import edu.uiuc.ncsa.security.delegation.storage.Client;

import org.masterportal.oauth2.server.MPOA2SE;

//import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ExceptionHandler;

import edu.uiuc.ncsa.security.oauth_2_0.OA2Utilities;
//import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandler;
//import edu.uiuc.ncsa.security.oauth_2_0.server.UII2;
//import edu.uiuc.ncsa.security.oauth_2_0.server.UIIRequest2;
//import edu.uiuc.ncsa.security.oauth_2_0.server.UIIResponse2;

import org.apache.commons.codec.digest.DigestUtils;


import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.CLIENT_SECRET;
import static edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys.CONSUMER_KEY;
import org.apache.http.HttpStatus;

import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.Identifier;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
//import java.util.LinkedList;
import java.util.ArrayList;
import java.util.List;
import java.util.Collection;
import java.net.URI;

import java.util.Base64;

import java.io.Writer;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import static edu.uiuc.ncsa.security.core.util.DateUtils.checkTimestamp;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 */
public class MPOA2SSHKeyServlet extends MyProxyDelegationServlet {
    private final String ACTION_PARAMETER = "action";
    private final String LABEL_PARAMETER = "label";
    private final String PUBKEY_PARAMETER = "pubkey";
    private final String DESCRIPTION_PARAMETER = "description";

    private final String ACTION_ADD	= "add";
    private final String ACTION_UPDATE	= "update";
    private final String ACTION_REMOVE	= "remove";
    private final String ACTION_GET	= "get";
    private final String ACTION_LIST	= "list";

    private final String SSH_KEY_START = "ssh-";

    private MPOA2SE se;
    private MyLoggingFacade logger;

    private boolean initDone = false;

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

    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
	return null;
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
	if (t.getMessage() != null) {
	    logger.info("Handling exception for: "+t.getMessage());
	}
	getExceptionHandler().handleException(t, request, response);
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
	// Get transaction for this request, based on access_token
	ServiceTransaction transaction = getAndVerifyTransaction(request);

	// Get the client_id: for PUT this is mandatory, for the others: if
	// present it should be valid and match the access_token
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
	String pubkey = null;
	String description = null;
	try {
	    action = OA2Utilities.getParam(request, ACTION_PARAMETER);
	    label = OA2Utilities.getParam(request, LABEL_PARAMETER);
	    pubkey = OA2Utilities.getParam(request, PUBKEY_PARAMETER);
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
		addKey(userName, label, pubkey, description);
		break;
	    case ACTION_UPDATE :
		// For adding client is mandatory
		if (client==null)   {
		    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
					      "Missing client for action "+action,
					      HttpStatus.SC_BAD_REQUEST);
		}
		updateKey(userName, label, pubkey, description);
		break;
	    case ACTION_REMOVE :
		removeKey(userName, label);
		break;
	    case ACTION_GET :
		SSHKey key = getKey(userName, label);
		writeKeys(response, java.util.Collections.singletonList(key));
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

    /**
     * adds entry for given user, label
     */
    private void addKey(String username, String label, String pubkey, String description) throws Throwable {
	// username and pubkey may not be empty
	if (username==null || username.isEmpty())   {
	    logger.error("Username is null or empty");
	    throw new GeneralException("Cannot get username");
	}
	if (pubkey==null || pubkey.isEmpty()) {
	    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "Missing mandatory pubkey", HttpStatus.SC_BAD_REQUEST);
	}

	// do sanity check on pubkey
	if (!isSSHPubKey(pubkey)) {
	    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "Pubkey does not look like a SSH public key", HttpStatus.SC_BAD_REQUEST);
	}

	// try to get store
	SQLSSHKeyStore store = (SQLSSHKeyStore)se.getSSHKeyStore();
	if ( store == null) {
	    logger.error("Cannot get SSHKeyStore");
	    throw new GeneralException("Could not get SSH KeyStore"); 
	}

	// Create new SSHKey object
	SSHKey key = new SSHKey(username, label, pubkey, description);

	// Check whether the ssh pubkey already exists
	if ( store.containsKey(key) )  {
	    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "SSH Pubkey is already registered", HttpStatus.SC_BAD_REQUEST);
	}

	// Store the new key
	try {
	    // when label isn't set, create one
	    if (label==null || label.isEmpty()) {
		key.setLabel(store.createLabel(username));
	    }
	    store.save(key);
	} catch (Exception e)	{
	    Throwable cause = e.getCause();
	    if (cause == null)
		logger.error("Cannot save key: "+e.getMessage());
	    else
		logger.error("Cannot save key: "+e.getMessage() + " (" + cause.getMessage() + ")");
	    throw new OA2GeneralError(OA2Errors.SERVER_ERROR, "Cannot add entry", HttpStatus.SC_INTERNAL_SERVER_ERROR);
	}
    }

    /**
     * update entry for given user, label
     */
    private void updateKey(String username, String label, String pubkey, String description) throws Throwable {
	// username and label may not be empty
	if (username==null || username.isEmpty())   {
	    logger.error("Username is null or empty");
	    throw new GeneralException("Cannot get username");
	}
	if (label==null || label.isEmpty()) {
	    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "Missing mandatory label", HttpStatus.SC_BAD_REQUEST);
	}

	// if we specified a pubkey, it must be non-empty and valid
	if (pubkey!=null)	{
	    if (pubkey.isEmpty())	{
		throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "SSH public key may not be empty", HttpStatus.SC_BAD_REQUEST);
	    }
	    if (!isSSHPubKey(pubkey)) {
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
	SSHKey value = store.get(new SSHKey(username, label));
	if (value==null) {
	    throw new OA2GeneralError("not_found", "No key to update found", HttpStatus.SC_NOT_FOUND);
	}

	// Update values
	if (pubkey != null)    {
	    value.setPubKey(pubkey);
	}
	if (description != null)    {
	    value.setDescription(description);
	}

	// Update the pubkey
	try {
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
     * removes entry for given username and label
     */
    private void removeKey(String userName, String label) throws Throwable {
	// username and label may not be empty
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
     * retrieves entry for given username, label
     */
    private SSHKey getKey(String username, String label) throws Throwable {
	// username and label may not be empty
	if (username==null || username.isEmpty() || label==null || label.isEmpty()) {
	    logger.error("Either username or label is empty");
	    throw new GeneralException("Need username and label for getting key");
	}

	// try to get store
	SQLSSHKeyStore store = (SQLSSHKeyStore)se.getSSHKeyStore();
	if ( store == null) {
	    throw new GeneralException("Could not get SSH KeyStore"); 
	}

	SSHKey key = null;
	try {
	    key = store.get(new SSHKey(username, label));
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
     * lists all entries for given username
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

	List<SSHKey> keys = store.getAll(userName);
	if (keys==null) {
	    throw new OA2GeneralError("not_found", "No key found", HttpStatus.SC_NOT_FOUND);
	}
    
	return keys;
    }


    /**
     * Writes each key to the response, using , as a separator between the
     * columns
     */
    private void writeKeys(HttpServletResponse response, List<SSHKey> keys)    {
	final char SEP = ',';
	try {
	    Writer writer = response.getWriter();
	    for (SSHKey key : keys)	{
		writer.write(key.getLabel());
		writer.append(SEP);
		writer.write(key.getUserName());
		writer.append(SEP);
		writer.write(key.getPubKey());
		writer.append(SEP);
		if (key.getDescription()!=null)
		    writer.write(key.getDescription());
		writer.append('\n');
	    }
	    writer.flush();
	    writer.close();
	} catch(IOException e)	{
	    logger.error("Error: Cannot write keys: "+e.getMessage());
	    throw new GeneralException("Cannot write keys");
	}
    }

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

    /**
     * Get access token from request, copy and paste from userinfo endpoint
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
     * Copy and paste from OA2CertServlet, except we allow here an absent client
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


}
