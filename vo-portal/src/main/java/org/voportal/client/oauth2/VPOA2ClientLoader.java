package org.voportal.client.oauth2;

import java.net.URI;

import javax.inject.Provider;

import org.apache.commons.configuration.tree.ConfigurationNode;

import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2AssetConverter;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2AssetSerializationKeys;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientLoader;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2SQLAssetStoreProvider;
import edu.uiuc.ncsa.security.delegation.client.DelegationService;
import edu.uiuc.ncsa.security.oauth_2_0.client.*;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.myproxy.oa4mp.client.loader.AbstractClientLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.*;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ConfigurationLoaderUtils;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2TokenForge;

import java.util.Collection;
import java.util.HashMap;

/**
 * <p>
 * Created by Jeff Gaynor<br>
 * on 4/2/15 at 2:01 PM
 */
public class VPOA2ClientLoader<T extends ClientEnvironment> extends OA2ClientLoader<T> {

	public static final String PROXY_ASSET_ENDPOINT = "getproxy";
	
	public static final long defaultProxyLifetime = 43200; // default is 12 hours, in seconds.
	
	
	public VPOA2ClientLoader(ConfigurationNode node) {
		super(node);
	}

	@Override
	public String getVersionString() {
		return "VO Portal OAuth2/OIDC client configuration loader version " + VERSION_NUMBER;
	}

	@Override
	public OA4MPServiceProvider getServiceProvider() {
		return new VPOA2MPService.VPOA2MPProvider(load());
	}

	public T createInstance(Provider<TokenForge> tokenForgeProvider, Provider<Client> clientProvider,
			HashMap<String, String> constants) {
		try {
			return (T) new VPOA2ClientEnvironment(myLogger, 
												constants, 
												getAccessTokenURI(), 
												getAuthorizeURI(),
												getCallback(), 
												getInitiateURI(), 
												getAssetURI(), 
												checkCertLifetime(),
												checkProxyLifetime(),
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
												getErrorPagePath(), 
												getRedirectPagePath(), 
												getSuccessPagePath(), 
												getSecret(), 
												getScopes());
		} catch (Throwable e) {
			throw new GeneralException("Unable to create client environment", e);
		}
	}

    protected long checkProxyLifetime() {
        String proxyLifetimeString = getCfgValue(VPClientXMLTags.PROXY_LIFETIME);
        if (proxyLifetimeString != null && !proxyLifetimeString.isEmpty()) {
            try {
                return Long.parseLong(proxyLifetimeString);
            } catch (Throwable t) {
                // if it fails, just say so, but keep going.
                myLogger.warn("Error: parsing default lifetime for proxy:" + t.getMessage());
            }
        }
        return defaultProxyLifetime;
    }
	
	
	
	AssetProvider assetProvider = null;

	@Override
	public AssetProvider getAssetProvider() {
		if (assetProvider == null) {
			assetProvider = new VPOA2AssetProvider();
		}
		return assetProvider;
	}

	@Override
	protected Provider<AssetStore> getAssetStoreProvider() {
		if (assetStoreProvider == null) {
			MultiAssetStoreProvider masp = new MultiAssetStoreProvider(cn, isDefaultStoreDisabled(),
					(MyLoggingFacade) loggerProvider.get());
			OA2AssetSerializationKeys keys = new VPOA2AssetSerializationKeys();
			OA2AssetConverter assetConverter = new VPOA2AssetConverter(keys, getAssetProvider());
			assetStoreProvider = masp;
			masp.addListener(new FSAssetStoreProvider(cn, getAssetProvider(), assetConverter));
			masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.POSTGRESQL_STORE,
					getPgConnectionPoolProvider(), getAssetProvider(), assetConverter));
			masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.MYSQL_STORE,
					getMySQLConnectionPoolProvider(), getAssetProvider(), assetConverter));
			masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.MARIADB_STORE,
					getMariaDBConnectionPoolProvider(), getAssetProvider(), assetConverter));
			// and a memory store, So only if one is requested it is available.
			masp.addListener(
					new TypedProvider<MemoryAssetStore>(cn, ClientXMLTags.MEMORY_STORE, ClientXMLTags.ASSET_STORE) {
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

	@Override
	protected Provider getDSP() {

		if (dsp == null) {
			dsp = new Provider<DelegationService>() {
				@Override
				public DelegationService get() {
					return new ProxyDelegationService(new AGServer2(createServiceClient(getAuthzURI())), // as
																											// per
																											// spec,
																											// request
																											// for
																											// AG
																											// comes
																											// through
																											// authz
																											// endpoint.
							new ATServer2(createServiceClient(getAccessTokenURI())),
							new PAServer2(createServiceClient(getAssetURI())),
							new UIServer2(createServiceClient(getUIURI())),
							new RTServer2(createServiceClient(getAccessTokenURI())), // as
																						// per
																						// spec,
																						// refresh
																						// token
																						// server
																						// is
																						// at
																						// same
																						// endpoint
																						// as
																						// access
																						// token
																						// server.
							new PPServer2(createServiceClient(getProxyAssetURI())));
				}
			};
		}

		return dsp;
	}

	protected URI getProxyAssetURI() {
		String x = getCfgValue(VPClientXMLTags.PROXY_ASSET_URI);
		checkProtocol(x);
		return createServiceURI(x, getBaseURI(), PROXY_ASSET_ENDPOINT);
	}

}
