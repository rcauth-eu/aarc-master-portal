package org.masterportal.oauth2.server.validators;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.masterportal.oauth2.server.MPOA2ServiceTransaction;
import org.masterportal.oauth2.server.exception.InvalidDNException;
import org.masterportal.oauth2.servlet.MPOA4MPConfigTags;

import edu.uiuc.ncsa.myproxy.MyProxyCredentialInfo;
import edu.uiuc.ncsa.security.core.Logable;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import eu.emi.security.authn.x509.impl.OpensslNameUtils;

/**
 * The DN of the store proxy is checked against a configurable claim 
 * returned by the Delegation Server. In case of mismatch the stored 
 * proxy is deemed invalid.
 * <p>
 * The required input configuration parameters are:
 * <ul>
 * <li>input_claim: the name of the claim containing the certificate DN</li>  
 * </ul> 
 *  
 * 
 * @author "Tamás Balogh"
 *
 */
public class DNValidator implements GetProxyRequestValidator {

	/* configuration input */
	
	public static final String INPUT_CLAIM = "input_claim";
	
	/* actual input */
	
	protected String inputClaim;
	
	/* other */
	
	protected Logable logger;
	
	@Override
	public void init(ConfigurationNode validatorNode, MyLoggingFacade logger) {
		
		this.logger = logger;
		
		// load every input 
		List inputNodes = validatorNode.getChildren( MPOA4MPConfigTags.MYPROXY_REQ_VALIDATOR_INPUT );
		
		for (int i=0; i<inputNodes.size(); i++) {
			ConfigurationNode inputNode = (ConfigurationNode) inputNodes.get(i);
			
			String inputName = Configurations.getFirstAttribute(inputNode, MPOA4MPConfigTags.MYPROXY_REQ_VALIDATOR_INPUT_NAME);
			String inputValue = (String) inputNode.getValue();
			
			if ( inputName == null && inputValue == null ) {
				throw new GeneralException("Invalid Validator input Configuration! Either 'name' or 'value' was not provided");
			} 
			
			// in this case we are expecting a single input, fail on any other input provided 
			if ( inputName.equals(INPUT_CLAIM) ) {
				inputClaim = inputValue;
			} else {
				throw new GeneralException("Invalid Validator input Configuration! Invalid input name : " + inputName);
			}
			
		}
	}

	@Override
	public void validate(MPOA2ServiceTransaction trans, HttpServletRequest request, HttpServletResponse response,
			MyProxyCredentialInfo info) throws Throwable {
		
		logger.debug("Starting Validator: " + this.getClass().getCanonicalName());

		// Only run when there is something to validate
		if (info == null)	{
			logger.debug("No (valid) proxy yet, skipping validation");

			return;
		}

		// The DN we have
		String storedDN = info.getRenewers();
		
		// The DN we expect
		String claimDN = null;
		Object certSubjectClaim = trans.getClaims().get(inputClaim);
		
		
		if ( certSubjectClaim == null ) {
			throw new GeneralException("Unable to find expected DN from claim : " + inputClaim);
		} else if ( certSubjectClaim instanceof String ) {
			claimDN = (String) certSubjectClaim;
			if ( claimDN.isEmpty() ) {
				throw new GeneralException("Expected DN from claim : " + inputClaim + " is empty!");
			}
		} else {
			// multi valued claim? wuut? something is off
			throw new GeneralException("Expected DN from claim : " + inputClaim + " is multi-valued!");
		}

		// convert the DN from the claim into openssl format 
		String opensslClaimDN = OpensslNameUtils.convertFromRfc2253( claimDN , false);
		
		if ( ! storedDN.equals(opensslClaimDN) ) {
			throw new InvalidDNException("The DN returned by MyProxy INFO (" + storedDN + ") did not match the value of the claim : "
					+ inputClaim + " (" + opensslClaimDN + ")");
		}
		
		logger.debug("Validation OK");
	}

}
