package org.masterportal.server.oauth2;

import javax.inject.Provider;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.masterportal.server.util.MPTransactionConverter;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.server.PPI2;

import edu.uiuc.ncsa.myproxy.oa4mp.server.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSTransactionStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore.DSFSTransactionStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.provider.DSSQLTransactionStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.TransactionConverter;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.storage.impl.TransactionMemoryStore;

public class MPOA2ServerLoader extends OA2ConfigurationLoader {

	public MPOA2ServerLoader(ConfigurationNode node) {
		super(node);
	}

    @Override
    public Provider<PAIssuer> getPAIProvider() {
        return new Provider<PAIssuer>() {
            @Override
            public PAIssuer get() {
                return new PPI2((TokenForge) getTokenForgeProvider().get(), getServiceAddress());
            }
        };
    }	
    
    
    
    @Override
    protected Provider getTSP() {
        if (tsp == null) {
            final DSTransactionProvider tp = new DSTransactionProvider<OA4MPServiceTransaction>();
            MPTransactionConverter<OA4MPServiceTransaction> tc = new MPTransactionConverter(tp,
                    (TokenForge) getTokenForgeProvider().get(),
                    (ClientStore<? extends Client>) getCSP().get());

            MultiDSTransactionStoreProvider storeProvider = new MultiDSTransactionStoreProvider(cn, isDefaultStoreDisabled(), (MyLoggingFacade) loggerProvider.get(), tp);
            storeProvider.addListener(new DSSQLTransactionStoreProvider(cn,
                    getMySQLConnectionPoolProvider(),
                    OA4MPConfigTags.MYSQL_STORE,
                    getCSP(),
                    tp,
                    getTokenForgeProvider(),
                    tc));
            storeProvider.addListener(new DSSQLTransactionStoreProvider(cn,
                               getMariaDBConnectionPoolProvider(),
                               OA4MPConfigTags.MARIADB_STORE,
                               getCSP(),
                               tp,
                               getTokenForgeProvider(),
                               tc));
            storeProvider.addListener(new DSSQLTransactionStoreProvider(cn,
                    getPgConnectionPoolProvider(),
                    OA4MPConfigTags.POSTGRESQL_STORE,
                    getCSP(),
                    tp,
                    getTokenForgeProvider(),
                    tc));
            storeProvider.addListener(new DSFSTransactionStoreProvider(cn, tp, getTokenForgeProvider(), tc));
            storeProvider.addListener(new TypedProvider<TransactionStore>(cn, OA4MPConfigTags.MEMORY_STORE, OA4MPConfigTags.TRANSACTIONS_STORE) {

                @Override
                public Object componentFound(CfgEvent configurationEvent) {
                    if (checkEvent(configurationEvent)) {
                        return get();
                    }
                    return null;
                }

                @Override
                public TransactionStore get() {
                    return new TransactionMemoryStore(tp);
                }
            });
            tsp = storeProvider;
        }
        return tsp;
    }
	
}
