package eu.rcauth.masterportal.server.validators;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.configuration.tree.ConfigurationNode;
import eu.rcauth.masterportal.server.MPOA2ServiceTransaction;
import eu.rcauth.masterportal.server.exception.InvalidRequestLifetimeException;
import eu.rcauth.masterportal.server.exception.ShortProxyLifetimeException;
import eu.rcauth.masterportal.servlet.MPOA4MPConfigTags;

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
 * Additionally it stores the value of the tolerance in the MPOA2ServiceTransaction.
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
    protected long maxProxyLifetime = -1;
    protected long defProxyLifetime = -1;
    protected long tolerance = -1;

    /* other */

    protected Logable logger;

    @Override
    public void init(ConfigurationNode validatorNode, MyLoggingFacade myLoggingFacade) throws NumberFormatException, GeneralException {

        this.logger = myLoggingFacade;

        // Get parent node for getting the default proxy lifetime
        ConfigurationNode grandParentNode = validatorNode.getParentNode().getParentNode();
        ConfigurationNode defaultLifetimeNode = Configurations.getFirstNode(grandParentNode, MPOA4MPConfigTags.MYPROXY_DEFAULT_LIFETIME);
        if (defaultLifetimeNode==null) {
            throw new GeneralException("grandParentNode "+grandParentNode.getName()+" has no node "+MPOA4MPConfigTags.MYPROXY_DEFAULT_LIFETIME);
        }
        defProxyLifetime = Long.parseLong( defaultLifetimeNode.getValue().toString());
        if (defProxyLifetime<=0)    {
            throw new GeneralException("Invalid "+MPOA4MPConfigTags.MYPROXY_DEFAULT_LIFETIME+" in node "+grandParentNode.getName()+": must be >0");
        }

        // load every input
        List<ConfigurationNode> inputNodes = validatorNode.getChildren( MPOA4MPConfigTags.MYPROXY_REQ_VALIDATOR_INPUT );

        // Note for collection foreach is better performing
        for (ConfigurationNode inputNode : inputNodes) {

            String inputName = Configurations.getFirstAttribute(inputNode, MPOA4MPConfigTags.MYPROXY_REQ_VALIDATOR_INPUT_NAME);
            String inputValue = (String) inputNode.getValue();

            if (inputName == null || inputValue == null) {
                throw new GeneralException("Invalid Validator input Configuration! Either 'name' or 'value' was not provided");
            }

            // in this case we are expecting two inputs, discard anything else
            if (inputName.equals(INPUT_MAX_PROXY_LIFETIME)) {
                maxProxyLifetime = Long.parseLong(inputValue);
                if (maxProxyLifetime <= 0) {
                    throw new GeneralException("Invalid Validator input Configuration! Invalid maxProxyLifetime: must be >0");
                }
            } else if (inputName.equals(INPUT_TOLERANCE)) {
                tolerance = Long.parseLong(inputValue);
                if (tolerance <= 0) {
                    throw new GeneralException("Invalid Validator input Configuration! Invalid tolerance: must be >0");
                }
            } else {
                throw new GeneralException("Invalid Validator input Configuration! Invalid input name : " + inputName);
            }

        }

        // Check we got both
        if (maxProxyLifetime<0 || tolerance<0) {
            throw new GeneralException("Invalid Validator input Configuration! Missing either "+INPUT_MAX_PROXY_LIFETIME+" or "+INPUT_TOLERANCE);
        }

        // Now verify the maximum versus default proxy lifetime
        long maxLifetime = maxProxyLifetime - tolerance;
        if (maxLifetime < defProxyLifetime)    {
            throw new GeneralException("Invalid Validator input Configuration! Effective maximum lifetime (" + maxLifetime + ") is smaller than default lifetime ("+ defProxyLifetime +")");
        }
    }

    @Override
    public void validate(MPOA2ServiceTransaction transaction, HttpServletRequest request, HttpServletResponse response,
             MyProxyCredentialInfo info) throws InvalidRequestLifetimeException, ShortProxyLifetimeException {

        logger.debug("Starting Validator: " + this.getClass().getCanonicalName());

        String reqLifetime = request.getParameter(OA2Constants.PROXY_LIFETIME);
        long maxLifetime = maxProxyLifetime - tolerance;

        // Store the retrieved tolerance in the transaction such that we can print it in an INFO request
        transaction.setProxyLifetimeTolerance(tolerance);

        long requestedLifetime;
        String lifetimelabel="Requested";
        // If no lifetime is requested, use the default lifetime
        if ( reqLifetime == null || reqLifetime.isEmpty() ) {
            // Override the label
            lifetimelabel="Default";

            // No requested lifetime, using default lifetime instead.
            requestedLifetime = defProxyLifetime;
            logger.debug("No requested lifetime value found! " +
                 "Server will fall back on configured default (" +
                 requestedLifetime + ")");
        } else {
            // requested lifetime is in seconds
            requestedLifetime = Long.parseLong( reqLifetime );

            // check against server maximum
            if ( requestedLifetime > maxLifetime ) {
                throw new InvalidRequestLifetimeException(
                    "Requested proxy lifetime (" + requestedLifetime +
                    ") is bigger then the server side maximum (" +
                    maxLifetime + "). Certificate will not get renewed." );
            }
        }

        // Only do remaining proxy lifetime verification if we already have
        // one (i.e. if the MyProxy server returned a valid answer)
        if (info != null)   {
            // check against remaining proxy lifetime
            // calculate the remaining max lifetime based on the store proxy validity
            long now = System.currentTimeMillis();
            long proxyEndTime = info.getEndTime();
            long maxLifetimeLeft = (proxyEndTime - now) / 1000;

            // compare values
            if ( maxLifetimeLeft < requestedLifetime ) {
            throw new ShortProxyLifetimeException(
                lifetimelabel + " lifetime (" + requestedLifetime +
                ") is larger that the remaining" + " proxy validity time ("
                + maxLifetimeLeft + "). Renewing certificate! ");
            }
        }


        logger.debug("Validation OK");

    }

}
