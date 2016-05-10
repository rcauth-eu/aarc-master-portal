package org.masterportal.oauth2.client.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.MyProxyFacadeProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2AssetConverter;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2AssetSerializationKeys;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientLoader;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2SQLAssetStoreProvider;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.masterportal.oauth2.client.MPOA2ClientEnvironment;
import org.masterportal.oauth2.client.MPOA2MPService;
import org.masterportal.oauth2.client.MPOA2MPService.MPOA2MPProvider;
import org.masterportal.oauth2.client.storage.MPOA2AssetConverter;
import org.masterportal.oauth2.client.storage.MPOA2AssetSerializationKeys;
import org.masterportal.oauth2.client.storage.impl.MPOA2AssetProvider;
import org.masterportal.oauth2.servlet.MPOA4MPConfigTags;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.*;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import javax.inject.Provider;

public class MPOA2ClientLoader<T extends ClientEnvironment> extends OA2ClientLoader<T> {
	
    AssetProvider assetProvider = null;

    public MPOA2ClientLoader(ConfigurationNode node) {
        super(node);
    }
  
    @Override
    public OA4MPServiceProvider getServiceProvider() {
        return new MPOA2MPService.MPOA2MPProvider(load());
    }	

    @Override
    public String getVersionString() {
        return "Master Portal OAuth2/OIDC client configuration loader version " + VERSION_NUMBER;
    }

    
    
    
    /**
     * Factory method. Override this to create the actual instance as needed.
     *
     * @param tokenForgeProvider
     * @param clientProvider
     * @param constants
     * @return
     */
    public T createInstance(Provider<TokenForge> tokenForgeProvider,
                            Provider<Client> clientProvider,
                            HashMap<String, String> constants) {
        try {
            return (T) new MPOA2ClientEnvironment(
                    myLogger, constants,
                    getAccessTokenURI(),
                    getAuthorizeURI(),
                    getCallback(),
                    getInitiateURI(),
                    getAssetURI(),
                    checkCertLifetime(),
                    getId(),
                    getSkin(),
                    isEnableAssetCleanup(),
                    getMaxAssetLifetime(),
                    getKeypairLifetime(),
                    getAssetProvider(),
                    clientProvider,
                    tokenForgeProvider,
                    getDSP(),
                    getAssetStoreProvider(),
                    isShowRedirectPage(),
                    requestProxies(),
                    getErrorPagePath(),
                    getRedirectPagePath(),
                    getSuccessPagePath(),
                    getSecret(),
                    getScopes(),
                    getMyProxyFacadeProvider(),
                    getMyProxyPassword()
            );
        } catch (Throwable e) {
            throw new GeneralException("Unable to create client environment", e);
        }
    }    
    
    
    @Override
    public AssetProvider getAssetProvider() {
        if(assetProvider == null){
            assetProvider = new MPOA2AssetProvider();
        }
        return assetProvider;
    }
    

    /*
     * Overrides the creation of AssetStore related classes to MPOA4Asset*
     */
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
    
    
    protected LinkedList<MyProxyFacadeProvider> mfp = null;

    protected LinkedList<MyProxyFacadeProvider> getMyProxyFacadeProvider() {
         if (mfp == null) {
             mfp = new LinkedList<MyProxyFacadeProvider>();
             // This is the global default for all instances. It can be overridden below.
             String defaultDN = Configurations.getFirstAttribute(cn, OA4MPConfigTags.MYPROXY_SERVER_DN);

             if (0 < cn.getChildrenCount(OA4MPConfigTags.MYPROXY)) {
                 List kids = cn.getChildren(OA4MPConfigTags.MYPROXY);
                 for (int i = 0; i < kids.size(); i++) {
                     ConfigurationNode currentNode = (ConfigurationNode) kids.get(i);
                     // Fix for CIL-196.
                     String currentDN  = Configurations.getFirstAttribute(currentNode, OA4MPConfigTags.MYPROXY_SERVER_DN);
                     mfp.add(new MyProxyFacadeProvider(((ConfigurationNode) kids.get(i)), (currentDN==null?defaultDN:currentDN)));
                 }

             } else {
                 // set up with defaults
                 mfp.add(new MyProxyFacadeProvider());
             }

         }
         return mfp;
     }    
    
    protected String getMyProxyPassword() {
    	ConfigurationNode node =  Configurations.getFirstNode(cn, MPOA4MPConfigTags.MYPROXY);
    	return Configurations.getFirstAttribute(node, MPOA4MPConfigTags.MYPROXY_PASSWORD);
    }
    
}
