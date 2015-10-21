package org.masterportal.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2AssetConverter;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2AssetSerializationKeys;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientLoader;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2SQLAssetStoreProvider;

import org.apache.commons.configuration.tree.ConfigurationNode;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.myproxy.oa4mp.client.loader.AbstractClientLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.*;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.client.DelegationService;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ConfigurationLoaderUtils;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.client.*;

import javax.inject.Provider;
import java.net.URI;
import java.util.Collection;
import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/2/15 at  2:01 PM
 */
public class MPOA2ClientLoader extends OA2ClientLoader {
	
    @Override
    public OA4MPServiceProvider getServiceProvider() {
        return new MPOA2MPService.MPOA2MPProvider(load());
    }	
	
    public MPOA2ClientLoader(ConfigurationNode node) {
        super(node);
    }

    @Override
    public String getVersionString() {
        return "CILogon OAuth2/OIDC client configuration loader version " + VERSION_NUMBER;
    }

    AssetProvider assetProvider = null;
    @Override
    public AssetProvider getAssetProvider() {
        if(assetProvider == null){
            assetProvider = new MPOA2AssetProvider();
        }
        return assetProvider;
    }
    
    
    @Override
    protected Provider<AssetStore> getAssetStoreProvider() {
        if (assetStoreProvider == null) {
            MultiAssetStoreProvider masp = new MultiAssetStoreProvider(cn, isDefaultStoreDisabled(), (MyLoggingFacade) loggerProvider.get());
            OA2AssetSerializationKeys keys = new MPOA2AssetSerializationKeys();
            OA2AssetConverter assetConverter = new MPOA2AssetConverter(keys, getAssetProvider());
            assetStoreProvider = masp;
            masp.addListener(new FSAssetStoreProvider(cn, getAssetProvider(), assetConverter));
            masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.POSTGRESQL_STORE, getPgConnectionPoolProvider(),
                    getAssetProvider(), assetConverter));
            masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.MYSQL_STORE, getMySQLConnectionPoolProvider(),
                    getAssetProvider(), assetConverter));
            masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.MARIADB_STORE, getMariaDBConnectionPoolProvider(),
                                getAssetProvider(), assetConverter));
            // and a memory store, So only if one is requested it is available.
            masp.addListener(new TypedProvider<MemoryAssetStore>(cn, ClientXMLTags.MEMORY_STORE, ClientXMLTags.ASSET_STORE) {
                @Override
                public Object componentFound(CfgEvent configurationEvent) {
                    if (checkEvent(configurationEvent)) {
                        return get();
                    }
                    return null;
                }

                @Override
                public MemoryAssetStore get() {
                    return new MemoryAssetStore(getAssetProvider());
                }
            });
        }
        return assetStoreProvider;
    }    

}
