package org.masterportal.oauth2.server.loader;

import javax.inject.Provider;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.masterportal.oauth2.server.MPOA2SE;
import org.masterportal.oauth2.server.MPOA2ServiceTransaction;
import org.masterportal.oauth2.server.storage.MPOA2TConverter;
import org.masterportal.oauth2.server.storage.MPOA2TransactionKeys;
import org.masterportal.oauth2.servlet.MPOA4MPConfigTags;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;


import static edu.uiuc.ncsa.myproxy.oa4mp.server.util.OA4MPIdentifierProvider.TRANSACTION_ID;
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
                    getClientSecretLength(),
                    getScopes(),
                    getScopeHandler(),
                    isRefreshTokenEnabled(),
                    getMyProxyPassword());
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
            throw new GeneralException("Error: Could not create the runtime environment", e);
        }
    }	
	
    protected String getMyProxyPassword() {
    	ConfigurationNode node =  Configurations.getFirstNode(cn, MPOA4MPConfigTags.MYPROXY);
    	return Configurations.getFirstAttribute(node, MPOA4MPConfigTags.MYPROXY_PASSWORD);
    }
    

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
	
}
