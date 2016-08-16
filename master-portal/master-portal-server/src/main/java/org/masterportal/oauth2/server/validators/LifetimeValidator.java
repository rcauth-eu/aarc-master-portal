package org.masterportal.oauth2.server.validators;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.masterportal.oauth2.server.MPOA2ServiceTransaction;
import org.masterportal.oauth2.server.exception.InvalidRequesLifetimeException;
import org.masterportal.oauth2.server.exception.ShortProxyLifetimeException;
import org.masterportal.oauth2.servlet.MPOA4MPConfigTags;

import edu.uiuc.ncsa.myproxy.MyProxyCredentialInfo;
import edu.uiuc.ncsa.security.core.Logable;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;

/**
 * Validate the requested proxy lifetime against the actual proxy lifetime remaining in the 
 * MyProxy Credential Store. This validator will check against invalid proxy lifetime requests 
 * that exceed server maximum, and against proxy lifetime requests that are larger than the 
 * time left in the stored proxy. The maximum proxy lifetime used by this validator is constructed
 * from the inputs by max_proxy_lifetime - tolerance
 * <p>
 * An empty reqLifetime is considered a valid request lifetime. 
 * 
 * <p>
 * The required input configuration parameters are:
 * <ul>
 * <li>max_proxy_lifetime: as set in the myproxy-server.conf (converted into seconds)</li>  
 * <li>tolerance: small timeframe in seconds (usually a day) which prevents 
 * the Delegation Server from being flooded with requests.</li>
 * </ul>
 * 
 * @author "Tamás Balogh"
 * 
 */
public class LifetimeValidator implements GetProxyRequestValidator {

	/* configuration input */
	
	public static final String INPUT_MAX_PROXY_LIFETIME = "max_proxy_lifetime";
	public static final String INPUT_TOLERANCE = "tolerance";
	
	/* actual input */
	
	// both of these are expressed in seconds
	protected long maxProxyLifetime;
	protected long tolerance;
	
	/* other */
	
	protected Logable logger;
	
	@Override
	public void init(ConfigurationNode validatorNode, MyLoggingFacade myLoggingFacade) {
		
		this.logger = myLoggingFacade;
		
		// load every input 
		List inputNodes = validatorNode.getChildren( MPOA4MPConfigTags.MYPROXY_REQ_VALIDATOR_INPUT );
		
		for (int i=0; i<inputNodes.size(); i++) {
			ConfigurationNode inputNode = (ConfigurationNode) inputNodes.get(i);
			
			String inputName = Configurations.getFirstAttribute(inputNode, MPOA4MPConfigTags.MYPROXY_REQ_VALIDATOR_INPUT_NAME);
			String inputValue = (String) inputNode.getValue();
			
			if ( inputName == null && inputValue == null ) {
				throw new GeneralException("Invalid Validator input Configuration! Either 'name' or 'value' was not provided");
			} 
			
			// in this case we are expecting two inputs, discard anything else
			if ( inputName.equals(INPUT_MAX_PROXY_LIFETIME) ) {
				maxProxyLifetime = Long.parseLong(inputValue);
				
			} else if ( inputName.equals(INPUT_TOLERANCE) ) {
				tolerance = Long.parseLong(inputValue);
				
			} else {
				throw new GeneralException("Invalid Validator input Configuration! Invalid input name : " + inputName);
			}
			
		}
	}

	@Override
	public void validate(MPOA2ServiceTransaction transaction, HttpServletRequest request, HttpServletResponse response,
			MyProxyCredentialInfo info) throws Throwable {
		
		logger.debug("Staring Validator: " + this.getClass().getCanonicalName());

		String reqLifetime = request.getParameter(OA2Constants.PROXY_LIFETIME);
		long maxLifetime = maxProxyLifetime - tolerance;
		
        if ( reqLifetime != null && ! reqLifetime.isEmpty() ) {
        	
	        // requested lifetime is in seconds
        	long requestedLifetime = Long.parseLong( reqLifetime );
        	
        	// check against server maximum
        	if ( requestedLifetime > maxLifetime ) {
        		throw new InvalidRequesLifetimeException("Requested proxy lifetime (" + requestedLifetime + ") is bigger then the server side"
        				+ " maximum (" + maxLifetime + "). Certificate will not get renewed." );
        	}
        	
        	// check against remaining proxy lifetime 
        	// calculate the remaining max lifetime based on the store proxy validity
	        long now = System.currentTimeMillis();
	        long proxyEndTime = info.getEndTime();
	        long maxLifetimeLeft = (proxyEndTime - now) / 1000;
	        
	        // compare values
	        if ( maxLifetimeLeft < requestedLifetime ) {
	        	throw new ShortProxyLifetimeException("Requested lifetime (" + requestedLifetime + ") is larger that the remaining"
	        			+ " proxy valitity time (" + maxLifetimeLeft + "). Renewing certificate! "); 
	        }
	    
	        logger.debug("Validation OK");
	        
        } else {
        	logger.debug("No requested lifetime value found! Server will fall back on configured default. Nothing to validate");
        }

		
	}

}
