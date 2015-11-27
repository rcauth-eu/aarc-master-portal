package org.masterportal.server.oauth2;

import javax.inject.Provider;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.masterportal.server.storage.MPOA2TConverter;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionKeys;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.server.PAI2;
import edu.uiuc.ncsa.security.oauth_2_0.server.PPI2;

import edu.uiuc.ncsa.myproxy.oa4mp.server.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.util.OA4MPIdentifierProvider.TRANSACTION_ID;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME_SPECIFIC_PART;

public class MPOA2ServerLoader<T extends ServiceEnvironmentImpl>  extends OA2ConfigurationLoader<T> {

	public MPOA2ServerLoader(ConfigurationNode node) {
		super(node);
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
                    getPPIProvider(),
                    getTokenForgeProvider(),
                    getConstants(),
                    getAuthorizationServletConfig(),
                    getUsernameTransformer(),
                    getPingable(),
                    getClientSecretLength(),
                    getScopes(),
                    getScopeHandler(),
                    isRefreshTokenEnabled());
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
            throw new GeneralException("Error: Could not create the runtime environment", e);
        }
    }	
	
	
    @Override
    public Provider<PAIssuer> getPAIProvider() {
        return new Provider<PAIssuer>() {
            @Override
            public PAIssuer get() {
                return new PAI2((TokenForge) getTokenForgeProvider().get(), getServiceAddress());
            }
        };
    }	
    
    
    public Provider<PAIssuer> getPPIProvider() {
        return new Provider<PAIssuer>() {
            @Override
            public PAIssuer get() {
                return new PPI2((TokenForge) getTokenForgeProvider().get(), getServiceAddress());
            }
        };
    }   
    
	@Override
	protected Provider<TransactionStore> getTSP() {
        IdentifiableProvider tp = new ST2Provider(new OA4MPIdentifierProvider(SCHEME, SCHEME_SPECIFIC_PART, TRANSACTION_ID, false));
        OA2TransactionKeys keys = new OA2TransactionKeys();
        OA2TConverter<OA2ServiceTransaction> tc = new MPOA2TConverter<OA2ServiceTransaction>(keys, tp, getTokenForgeProvider().get(), getClientStoreProvider().get());
        return getTSP(tp,  tc);
	}

    
}
