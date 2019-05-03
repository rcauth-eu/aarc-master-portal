package eu.rcauth.masterportal.client.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.server.MyProxyFacadeProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientLoader;

import org.apache.commons.configuration.tree.ConfigurationNode;
import eu.rcauth.masterportal.client.MPOA2Asset;
import eu.rcauth.masterportal.client.MPOA2ClientEnvironment;
import eu.rcauth.masterportal.client.MPOA2MPService;
import eu.rcauth.masterportal.client.storage.MPOA2AssetConverter;
import eu.rcauth.masterportal.client.storage.MPOA2AssetSerializationKeys;
import eu.rcauth.masterportal.client.storage.impl.MPOA2AssetProvider;
import eu.rcauth.masterportal.client.storage.sql.MPOA2SQLAssetStoreProvider;
import eu.rcauth.masterportal.servlet.MPOA4MPConfigTags;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.MultiAssetStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.FSAssetStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.MemoryAssetStore;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import javax.inject.Provider;

/**
 *  Load and configure the MP Client. This loader got extended with the following capabilities:
 *  <p>
 *  - support for creating extended asset store ( {@link MPOA2Asset} );
 *  <p>
 *  - support the loading of myproxy connection configuration from the config file;
 *  @author Tamás Balogh
 */
public class MPOA2ClientLoader<T extends ClientEnvironment> extends OA2ClientLoader<T> {

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

    // Needed for the cast to T
    @SuppressWarnings("unchecked")
    public T createInstance(Provider<TokenForge> tokenForgeProvider,
                            Provider<Client> clientProvider,
                            HashMap<String, String> constants) {
        try {
            // Note we suppress an unchecked cast to T
            return (T)new MPOA2ClientEnvironment(
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
                    getWellKnownURI(),
                    isOIDCEnabled(),
                    isShowIDToken(),
                    getMyProxyFacadeProvider(),
                    getMyProxyPassword()
            );
        } catch (Throwable e) {
            throw new GeneralException("Unable to create client environment", e);
        }
    }


    /* ASSET EXTENSION */

    private AssetProvider assetProvider = null;

    @Override
    public AssetProvider getAssetProvider() {
        if(assetProvider == null)
            assetProvider = new MPOA2AssetProvider();
        return assetProvider;
    }

    /**
     *  Overrides the creation of AssetStore related classes. Instead of OA2Asset object, use
     *  the extended MPOA2Asset
     */
    @Override
    protected Provider<AssetStore> getAssetStoreProvider() {
        if (assetStoreProvider == null) {
            MultiAssetStoreProvider masp = new MultiAssetStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get());
            MPOA2AssetSerializationKeys keys = new MPOA2AssetSerializationKeys();
            // We suppress unchecked assignment since we're using MPOA2Asset instead of Asset, hence no generics
            @SuppressWarnings("unchecked")
            MPOA2AssetConverter assetConverter = new MPOA2AssetConverter(keys, getAssetProvider());
            assetStoreProvider = masp;

            // File storage
            masp.addListener(new FSAssetStoreProvider(cn, getAssetProvider(), assetConverter));

            // Database storage
            masp.addListener(new MPOA2SQLAssetStoreProvider(cn, ClientXMLTags.MYSQL_STORE, getMySQLConnectionPoolProvider(),
                                                            getAssetProvider(), assetConverter));
            masp.addListener(new MPOA2SQLAssetStoreProvider(cn, ClientXMLTags.MARIADB_STORE, getMariaDBConnectionPoolProvider(),
                                                            getAssetProvider(), assetConverter));

            // this is experimental. it might just work out of the box
            //masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.POSTGRESQL_STORE, getPgConnectionPoolProvider(),
            //                                              getAssetProvider(), assetConverter));

            // and a memory store, So only if one is requested it is available.
            masp.addListener(new TypedProvider<MemoryAssetStore>(cn, ClientXMLTags.MEMORY_STORE, ClientXMLTags.ASSET_STORE) {
                @Override
                public Object componentFound(CfgEvent configurationEvent) {
                    if (checkEvent(configurationEvent))
                        return get();
                    return null;
                }

                // We suppress unchecked assignment since we're using MPOA2Asset instead of Asset
                @Override
                @SuppressWarnings("unchecked")
                public MemoryAssetStore get() {
                    return new MemoryAssetStore(getAssetProvider());
                }
            });
        }
        return assetStoreProvider;
    }


    /* MYPROXY SERVER CONNECTOR */

    protected LinkedList<MyProxyFacadeProvider> mfp = null;

    protected LinkedList<MyProxyFacadeProvider> getMyProxyFacadeProvider() {
        if (mfp == null) {
            mfp = new LinkedList<>();
            // This is the global default for all instances. It can be overridden below.
            String defaultDN = Configurations.getFirstAttribute(cn, OA4MPConfigTags.MYPROXY_SERVER_DN);

            if (0 < cn.getChildrenCount(OA4MPConfigTags.MYPROXY)) {
                List<ConfigurationNode> kids = cn.getChildren(OA4MPConfigTags.MYPROXY);
                for (ConfigurationNode currentNode : kids) {
                    // Fix for CIL-196.
                    String currentDN = Configurations.getFirstAttribute(currentNode, OA4MPConfigTags.MYPROXY_SERVER_DN);
                    mfp.add(new MyProxyFacadeProvider(currentNode, (currentDN == null ? defaultDN : currentDN)));
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
