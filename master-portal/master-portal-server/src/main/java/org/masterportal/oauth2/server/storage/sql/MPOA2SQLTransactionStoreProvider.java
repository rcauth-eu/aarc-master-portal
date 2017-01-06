package org.masterportal.oauth2.server.storage.sql;

import org.masterportal.oauth2.server.storage.MPOA2TransactionKeys;
import org.masterportal.oauth2.server.storage.sql.table.MPOA2TransactionTable;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2SQLTransactionStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientStoreProvider;
// Updated next one
//import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.DSSQLTransactionStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.DSSQLTransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;

public class MPOA2SQLTransactionStoreProvider<T extends DSSQLTransactionStore> extends OA2SQLTransactionStoreProvider<T> {

    public MPOA2SQLTransactionStoreProvider(ConfigurationNode config,
            ConnectionPoolProvider<? extends ConnectionPool> cpp,
            String type,
            MultiDSClientStoreProvider clientStoreProvider,
            Provider<? extends OA2ServiceTransaction> tp,
            Provider<TokenForge> tfp,
            MapConverter converter) {

			super(config, cpp, type, clientStoreProvider, tp, tfp, converter);
			}

	@Override
	public T get() {
			return newInstance(new MPOA2TransactionTable((MPOA2TransactionKeys)converter.keys, getSchema(), getPrefix(), getTablename()));
	}	
	
}
