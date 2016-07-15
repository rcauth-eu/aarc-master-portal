package org.masterportal.oauth2.client.storage.sql;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.masterportal.oauth2.client.storage.MPOA2AssetSerializationKeys;
import org.masterportal.oauth2.client.storage.sql.table.MPOA2AssetStoreTable;

import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreTable;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.SQLAssetStore;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2SQLAssetStoreProvider;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;

public class MPOA2SQLAssetStoreProvider extends OA2SQLAssetStoreProvider {

    public MPOA2SQLAssetStoreProvider(ConfigurationNode config, String storeType, ConnectionPoolProvider<? extends ConnectionPool> cpp, AssetProvider assetProvider, MapConverter converter) {
        super(config, storeType, cpp, assetProvider, converter);
    }	
    
    
    @Override
    public SQLAssetStore get() {
        return newInstance(new MPOA2AssetStoreTable(
                (MPOA2AssetSerializationKeys)converter.keys, getSchema(),
                getPrefix(),
                getTablename() == null ? AssetStoreTable.DEFAULT_TABLENAME : getTablename()));
    }
	
}
