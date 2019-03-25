package eu.rcauth.masterportal.server.servlet;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;

import java.security.KeyPair;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.myproxy.MyProxyCredentialInfo;
import edu.uiuc.ncsa.myproxy.exception.MyProxyCertExpiredException;
import edu.uiuc.ncsa.myproxy.exception.MyProxyNoUserException;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ProxyServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;

import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;

import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import org.apache.http.HttpStatus;

import eu.rcauth.masterportal.MPClientContext;
import eu.rcauth.masterportal.server.MPOA2RequestForwarder;
import eu.rcauth.masterportal.server.MPOA2SE;
import eu.rcauth.masterportal.server.MPOA2ServiceTransaction;
import eu.rcauth.masterportal.server.exception.InvalidDNException;
import eu.rcauth.masterportal.server.exception.InvalidRequestLifetimeException;
import eu.rcauth.masterportal.server.exception.ShortProxyLifetimeException;
import eu.rcauth.masterportal.server.validators.GetProxyRequestValidator;

public class MPOA2ProxyServlet extends OA2ProxyServlet {
	
	/* OVERRIDEN METHODS */
	
	/**
	 *  Checks if the request has a proxy lifetime value. If not, if will override the 
	 *  transaction default lifetime to a Master Portal specific default lifetime value.
	 *  See the Master Portal Server cfg.xml for the default lifetime setting.
	 * 
	 *  @param iResponse The response object being constructed
	 *  @return The service transaction built for this session 
	 */
	@Override
	public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
		ServiceTransaction trans =  super.verifyAndGet(iResponse);
		
		MPOA2SE se = (MPOA2SE) getServiceEnvironment();
		Map params = iResponse.getParameters();
		
        if(!params.containsKey(OA2Constants.PROXY_LIFETIME)) {
        	trans.setLifetime( 1000 * se.getMyproxyDefaultLifetime() );
        	debug("6.a. Setting proxy lifetime to Master Portal Server default value = " + trans.getLifetime());
        }
        
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
        	String myproxyPasswrod  = ((MPOA2SE)getServiceEnvironment()).getMyproxyPassword();
        	debug("Creating new MP connection with username: " + st.getUsername() + " and lifetime: " + st.getLifetime());
            createMPConnection(st.getIdentifier(), st.getUsername(), myproxyPasswrod, st.getLifetime());
        }
	}
	
	/**
	 *  Prepare for the upcoming /getproxy request. In order to assure that the
	 *  MyProxy GET command will succeed, first this method will make sure that
	 *  the MyProxy Credential Store has a valid proxy for the user, by
	 *  executing a MyProxy INFO command first. If the results of the MyProxy
	 *  INFO are unsatisfactory, this method will forward a /getcert request to
	 *  the Delegation Server (via the Master Portal Client). Once that all
	 *  succeeds, a new proxy key+CSR is created.
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
		
		// establish a myproxy connection so that we can execute an INFO command
		checkMPConnection(trans);
        MyProxyConnectable mpc = getMPConnection(trans);
        
        // track if we need to forward the request and obtain a new long-lived
		// proxy
	    boolean requestNewCert = true;
	   
		// Need to split the try-catch blocks into two: the validators are
		// expected to run AFTER the myproxy info call, but at that stage, we
		// still might need to fail on the input request parameters such as the
		// requested proxy lifetime. This is certainly not ideal, but we
		// currently have only one type of validator.
		MyProxyCredentialInfo mpc_info = null;
        try {
	        
        	// executing MyProxy INFO
        	info("Executing MyProxy INFO");
        	mpc_info = mpc.doInfo();
	        debug("Valid user certificate found!");
			// set flag to false for now, it might still change after running the
			// validators
			requestNewCert = false;
	        
	        debug("--- INFO ---");
	        debug(mpc_info.toString());
	        debug("--- INFO ---");

        } catch (MyProxyNoUserException e) {
        	debug("No user found in MyProxy Credential Store!");
        	debug(e.getMessage());
        	requestNewCert = true;
        } catch (MyProxyCertExpiredException e) {
        	debug("User certificate from MyProxy Credential Store is expired!");
        	debug(e.getMessage());
        	requestNewCert = true;
        } catch (Throwable e) {
			// myproxy info failed for some unknown reason: don't try to fix
        	if ( e instanceof GeneralException ) {
        		throw e;
        	} else {
        		throw new GeneralException("MyProxy info failed", e);
        	}
        }
	  
		try {
			// execute request validator in order. Note that some validators
			// will not do anything in case of empty mpc_info, but we should
			// still run them now.
			for ( GetProxyRequestValidator validator : se.getValidators()) {
				validator.validate(trans, request, response, mpc_info);
			}
		} catch (ShortProxyLifetimeException e) {
			debug("The requested lifetime exceeds remaining proxy lifetime!");
			debug(e.getMessage());
			requestNewCert = true;
		} catch (InvalidDNException e) {
			debug("Invalid Proxy! The cached proxy DN does not match the DN returned by the Delegation Server!");
			debug(e.getMessage());
			requestNewCert = true;
		} catch (InvalidRequestLifetimeException e) {	// Fail on this one
			debug("The requested lifetime exceeds server maximum!");
			String mesg=e.getMessage();
			// don't request new certificate in this case, it's a user error
			throw new OA2GeneralError(mesg, OA2Errors.INVALID_REQUEST, mesg, HttpStatus.SC_BAD_REQUEST);
		} catch (Throwable e) {
			if ( e instanceof GeneralException ) {
				throw e;
			} else {
				throw new GeneralException("Validation of /getproxy request failed", e);
			}
		}
        
        if (requestNewCert) {
        	info("2.a. Proxy retrieval failed! Asking for a new user certificate ...");
        	// call /forwardgetcert on the Master Portal Client component
        	forwardRealCertRequest(trans, request, response);
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
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new GeneralException("Could not create cert request", e);
        }
        
        // insert a CSR and generated keypair into the transaction 
        trans.setCertReq(certReq);
        trans.setKeypair(keyPair);
        		
	}

	/* HELPER METHODS */
	
	/**
	 * Forward the currently pending request to the Master Portal Client's MP_CLIENT_FWGETCERT_ENDPOINT
	 * endpoint. This method should be called if a new certificate is needed in the Credential Store, since
	 * this will set of a /getcert call to the Delegation Server. 
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
		
		MPOA2RequestForwarder.forwardRequest(request, response, dispatcher, true);
		
	    info("Ended forwarding getCert to Master Portal Client");
	    
	}
	
}
