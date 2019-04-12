package eu.rcauth.masterportal.server.validators;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.configuration.tree.ConfigurationNode;
import eu.rcauth.masterportal.server.MPOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.MyProxyCredentialInfo;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

/**
 * GetProxy Request Validator Interface
 * <p>
 * Implement this interface if you want to validate the request parameters or
 * MyProxy INFO of the existing proxy certificate before executing the MyProxy
 * GET to return it.
 * 
 * @author "Tamás Balogh"
 *
 */
public interface GetProxyRequestValidator {

	/**
	 * Initialize validator class. Use this method to load any required input from the 
	 * configuration file. The validatorNode give as a parameter is exected to have the
	 * following form:
	 * <p>
	 * 
	 * {@code
	 * <validator>
	 * 		<input name"input_name">input_value</input>
	 * </validator>
	 * }
	 * 
	 * <p>
	 * Load input of the form input_name=input_value
	 * 
	 * @param validatorNode The validator configuration node
	 * @param myLoggingFacade The logger to use for logging
	 */
	void init(ConfigurationNode validatorNode, MyLoggingFacade myLoggingFacade);
	
	
	/**
	 * Validator method being called after returning MyProxy INFO. This method is expected
	 * to implement the validation logic and return in case of success. In case of failure
	 * it is expected to return an Exception. It MUST allow an null valued
	 * MyProxyCredentialInfo.
	 * 
	 * @param transaction The current transaction
	 * @param request The current session request
	 * @param response The current session response
	 * @param info The INFO returned by MyProxy
	 * @throws Throwable The Exception thrown for an invalid request.
	 */
	void validate(MPOA2ServiceTransaction transaction, HttpServletRequest request, HttpServletResponse response, MyProxyCredentialInfo info) throws Throwable;
	
}
