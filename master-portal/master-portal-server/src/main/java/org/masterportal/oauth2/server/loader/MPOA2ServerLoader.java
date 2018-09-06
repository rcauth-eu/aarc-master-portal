package org.masterportal.oauth2.server.loader;

import javax.inject.Provider;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.masterportal.oauth2.server.MPOA2SE;
import org.masterportal.oauth2.server.MPOA2ServiceTransaction;
import org.masterportal.oauth2.server.storage.MPOA2TConverter;
import org.masterportal.oauth2.server.storage.MPOA2TransactionKeys;
import org.masterportal.oauth2.server.storage.sql.MPOA2SQLTransactionStoreProvider;

import org.masterportal.oauth2.server.storage.SSHKeyStore;
import org.masterportal.oauth2.server.storage.SSHKeyIdentifierProvider;
import org.masterportal.oauth2.server.storage.SSHKeyConverter;
import org.masterportal.oauth2.server.storage.SSHKeyKeys;
import org.masterportal.oauth2.server.storage.impl.SSHKeyProvider;
import org.masterportal.oauth2.server.storage.impl.MultiSSHKeyStoreProvider;
import org.masterportal.oauth2.server.storage.sql.SQLSSHKeyStoreProvider;

import org.masterportal.oauth2.server.validators.GetProxyRequestValidator;
import org.masterportal.oauth2.servlet.MPOA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2SQLTransactionStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.*;
// Added this one
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientStoreProvider;
// Updated this one
//import edu.uiuc.ncsa.myproxy.oa4mp.server.util.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;

//import static edu.uiuc.ncsa.myproxy.oa4mp.server.util.OA4MPIdentifierProvider.TRANSACTION_ID;
import static edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider.TRANSACTION_ID;

import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME_SPECIFIC_PART;

public class MPOA2ServerLoader<T extends ServiceEnvironmentImpl>  extends OA2ConfigurationLoader<T> {

    public MPOA2ServerLoader(ConfigurationNode node) {
	super(node);
    }

    @Override
    public String getVersionString() {
	return "Master Portal OAuth2/OIDC server configuration loader version " + VERSION_NUMBER;
    }
    
    @Override
    public T createInstance() {
        try {
            return (T) new MPOA2SE(loggerProvider.get(),
                    getTransactionStoreProvider(),
                    getClientStoreProvider(),
		    getSSHKeyStoreProvider(),
                    getMaxAllowedNewClientRequests(),
                    getRTLifetime(),
                    getClientApprovalStoreProvider(),
                    getMyProxyFacadeProvider(),
                    getMailUtilProvider(),
                    getMP(),
                    getAGIProvider(),
                    getATIProvider(),
                    getPAIProvider(),
                    getTokenForgeProvider(),
                    getConstants(),
                    getAuthorizationServletConfig(),
                    getUsernameTransformer(),
                    getPingable(),
		    getMpp(),	// see OA2ConfigurationLoader
		    getMacp(),	// see OA2ConfigurationLoader
                    getClientSecretLength(),
                    getScopes(),
                    getScopeHandler(),
		    getLdapConfiguration(),
                    isRefreshTokenEnabled(),
		    isTwoFactorSupportEnabled(),
		    getMaxClientRefreshTokenLifetime(),
		    getJSONWebKeys(),	// see OA2ConfigurationLoader
                    getMyProxyPassword(),
                    getMyProxyDefaultLifetime(),
		    getMaxSSHKeys(),
		    getAutoRegisterEndpoint(),
                    getValidators(),
		    getIssuer());   // see OA2ConfigurationLoader
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
            throw new GeneralException("Error: Could not create the runtime environment", e);
        }
    }

    protected MultiSSHKeyStoreProvider sshKeySP;

    public Provider<SSHKeyStore> getSSHKeyStoreProvider() {
    	if ( sshKeySP == null ) {
	     sshKeySP = new MultiSSHKeyStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get(), null, null);
	     
	     SSHKeyProvider provider = new SSHKeyProvider( new SSHKeyIdentifierProvider() );
	     SSHKeyConverter converter = new SSHKeyConverter( new SSHKeyKeys(), provider);

	     sshKeySP.addListener( new SQLSSHKeyStoreProvider(cn,
			      getMySQLConnectionPoolProvider(),
				      OA4MPConfigTags.MYSQL_STORE, 
				      converter, 
				      provider) );    

	     sshKeySP.addListener( new SQLSSHKeyStoreProvider(cn,
			      getMariaDBConnectionPoolProvider(),
				      OA4MPConfigTags.MARIADB_STORE, 
				      converter, 
				      provider) );      		 
	     
	     // TODO: The backend for this is not written. yet. But it might just work out of the box
	     /*
	     sshKeySP.addListener( new SQLSSHKeyStoreProvider(cn,
			      getPgConnectionPoolProvider(),
			      OA4MPConfigTags.POSTGRESQL_STORE, 
			      converter, 
			      provider) );
	     */
    		 
    	}
    	return sshKeySP;
    }

    /* ADDITIONAL MYPROXY SERVER CONFIGURATIONS */
    
    protected String getMyProxyPassword() {
	ConfigurationNode node =  Configurations.getFirstNode(cn, MPOA4MPConfigTags.MYPROXY);
	return Configurations.getFirstAttribute(node, MPOA4MPConfigTags.MYPROXY_PASSWORD);
    }
    
    protected long getMyProxyDefaultLifetime() {
	ConfigurationNode node =  Configurations.getFirstNode(cn, MPOA4MPConfigTags.MYPROXY);
	ConfigurationNode lifetimeNode =  Configurations.getFirstNode(node, MPOA4MPConfigTags.MYPROXY_DEFAULT_LIFETIME);
	if (lifetimeNode==null)	{
	    throw new GeneralException("Missing "+MPOA4MPConfigTags.MYPROXY_DEFAULT_LIFETIME+" in node "+node.getName());
	}
	return Long.parseLong( lifetimeNode.getValue().toString() );
    }
    
    /* GETCERT REQUEST VALIDATORS */
    
    protected GetProxyRequestValidator[] getValidators() {
	
	// get the list of all validators
	ConfigurationNode mpNode =  Configurations.getFirstNode(cn, MPOA4MPConfigTags.MYPROXY);
	ConfigurationNode validatorsNode =  Configurations.getFirstNode(mpNode, MPOA4MPConfigTags.MYPROXY_REQ_VALIDATORS);
	
	if ( validatorsNode != null ) {
	    
	    // count validators
	    int validatorCnt = validatorsNode.getChildrenCount( MPOA4MPConfigTags.MYPROXY_REQ_VALIDATOR );
	    GetProxyRequestValidator[] validators = new GetProxyRequestValidator[ validatorCnt ];
	    int i = 0;

	    for ( Object node : validatorsNode.getChildren( MPOA4MPConfigTags.MYPROXY_REQ_VALIDATOR ) ) {
		
		// get the validator handler class name
		ConfigurationNode validatorNode = (ConfigurationNode) node;
		String validatorClass = Configurations.getFirstAttribute(validatorNode, 
									 MPOA4MPConfigTags.MYPROXY_REQ_VALIDATOR_HANDLER);

		if ( validatorClass == null || validatorClass.isEmpty() ) {
		    throw new GeneralException("Invalid validator configuration! Missing validator handler!");
		} else {
		    
		    try {
			    
			// create new class instance of validator
                        Class<?> k = Class.forName(validatorClass);
                        Object x = k.newInstance();
                        
                        if ( ! (x instanceof GetProxyRequestValidator) ) {
			    throw new Exception("Invalid validator handler " + validatorClass + " ! Every validator class should "
                        			+ "implement the " + GetProxyRequestValidator.class.getCanonicalName() + " interface");
                        }

                        // cast and init class with required input
                        GetProxyRequestValidator v = (GetProxyRequestValidator) x;
                        v.init(validatorNode, loggerProvider.get());
                        
                        // save validator
                        validators[i] = v;
                        i++;
                        
		    } catch (Exception e)  {
			throw new GeneralException("Invalid validator configuration! Cannot create instance of handler " + validatorClass,e);
		    }
		    
    		}
    	    }
    	    // return validators, empty or not
    	    return validators;
    	}
    	// return empty validators 
    	return new GetProxyRequestValidator[0];
    }
    
    /* CUSTOM TRANSACTION */

    public static class MPST2Provider extends DSTransactionProvider<OA2ServiceTransaction> {

        public MPST2Provider(IdentifierProvider<Identifier> idProvider) {
            super(idProvider);
        }

        @Override
        public OA2ServiceTransaction get(boolean createNewIdentifier) {
	    return new MPOA2ServiceTransaction(createNewId(createNewIdentifier));
        }
        
    }

    
    @Override
    protected Provider<TransactionStore> getTSP() {
        IdentifiableProvider tp = new MPST2Provider(new OA4MPIdentifierProvider(SCHEME, SCHEME_SPECIFIC_PART, TRANSACTION_ID, false));
        MPOA2TransactionKeys keys = new MPOA2TransactionKeys();
        MPOA2TConverter<MPOA2ServiceTransaction> tc = new MPOA2TConverter<MPOA2ServiceTransaction>(keys, tp, getTokenForgeProvider().get(), getClientStoreProvider().get());
        return getTSP(tp,  tc);
    }


    @Override
    protected OA2SQLTransactionStoreProvider createSQLTSP(ConfigurationNode config,
							  ConnectionPoolProvider<? extends ConnectionPool> cpp,
							  String type,
							  MultiDSClientStoreProvider clientStoreProvider,
							  Provider<? extends OA2ServiceTransaction> tp,
							  Provider<TokenForge> tfp,
							  MapConverter converter){
	return new MPOA2SQLTransactionStoreProvider(config,cpp,type,clientStoreProvider,tp,tfp,converter);
    }
    
    /* SSH KEY CONFIGURATION */

    protected int getMaxSSHKeys() {
	MyLoggingFacade logger = loggerProvider.get();
	ConfigurationNode node =  Configurations.getFirstNode(cn, MPOA4MPConfigTags.SSH_KEYS);
	String maxValue = Configurations.getFirstAttribute(node, MPOA4MPConfigTags.MAX_SSH_KEYS);
	int max = -1;
	if (maxValue != null && !maxValue.isEmpty())	{
	    try {
		max=Integer.parseInt(maxValue);
		logger.info("Using maximum "+max+" keys per user");
	    } catch (Exception e)   {
		logger.warn("Value of " + MPOA4MPConfigTags.MAX_SSH_KEYS +
			    " in node "+node.getName()+" is not a valid integer");
	    }
	} else {
	    logger.info("No (valid) maximum keys found");
	}
	return max;
    }

    /* Configuration of autoregistration endpoint */

    protected boolean getAutoRegisterEndpoint() {
	MyLoggingFacade logger = loggerProvider.get();
	// Default is false
	boolean autoRegisterEndpoint = false;
	String x = Configurations.getFirstAttribute(cn, MPOA4MPConfigTags.AUTOREGISTER_ENDPOINT_ENABLED);
	if (x == null) {
	    autoRegisterEndpoint = false;
	    logger.info("Attribute " +
			MPOA4MPConfigTags.AUTOREGISTER_ENDPOINT_ENABLED +
			" is unset, autoregistration endpoint is disabled.");
	} else {
	    autoRegisterEndpoint = Boolean.parseBoolean(x);
	    logger.info("Autoregistration endpoint is " +
			(autoRegisterEndpoint==true ? "ENABLED" : "disabled") +
			".");
	}
        return autoRegisterEndpoint;
    }
    
}
