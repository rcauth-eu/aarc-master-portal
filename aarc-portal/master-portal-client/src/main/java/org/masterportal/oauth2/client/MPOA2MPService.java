package org.masterportal.oauth2.client;

import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

import edu.uiuc.ncsa.myproxy.MPConnectionProvider;
import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.client.request.DelegatedAssetResponse;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.MyX509Certificates;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;

/**
 * <p>
 * Created by Jeff Gaynor<br>
 * on 8/21/15 at 12:03 PM
 */
public class MPOA2MPService extends OA2MPService {

	public static class MPOA2MPProvider extends OA4MPServiceProvider {
		public MPOA2MPProvider(ClientEnvironment clientEnvironment) {
			super(clientEnvironment);
		}

		@Override
		public MPOA2MPService get() {
			return new MPOA2MPService(clientEnvironment);
		}
	}

	protected MyLoggingFacade logger = null;

	public MPOA2MPService(ClientEnvironment environment) {
		super(environment);

		if (getEnvironment() != null) {
			logger = getEnvironment().getMyLogger();
		} else {
			// always return one so even if things blow up some record
			// remains...
			logger = new MyLoggingFacade("NOENV-MasterPortal");
		}
	}

	protected MyProxyConnectable createMPConnection(Identifier identifier, String userName, String password,
			long lifetime, String loa) throws GeneralSecurityException {
		
		MPConnectionProvider facades = new MPConnectionProvider(logger, 
																((MPOA2ClientEnvironment)getEnvironment()).getMyProxyServices() );
		MyProxyConnectable mpc = facades.findConnection(identifier, userName, password, loa, lifetime);
		return mpc;
	}

	@Override
	public AssetResponse getCert(OA2Asset a, ATResponse2 atResponse2) {
		AssetResponse par = super.getCert(a, atResponse2);

		logger.debug("Certificate request ended, trying to store the received cert in the Credential Store");
		
		if (par.getCredential() instanceof MyX509Certificates) {

			logger.debug("Using MyProxy PUT to store credential");
			
			// User EE Certificate use PUT
			try {
				putCert(par,a);
			} catch (Throwable e) {
				throw new GeneralException(e);
			}
			
		} else {

			logger.debug("Using MyProxy STORE to store credential");
			
			// Proxy Certificate use STORE

		}

		return par;
	}

	public void putCert(AssetResponse assetResp, OA2Asset asset) throws Throwable {

		String myproxyPasswrod  = ((MPOA2ClientEnvironment)getEnvironment()).getMyproxyPassword();
		long lifetime = getEnvironment().getCertLifetime();
		
		MyProxyConnectable mp = createMPConnection(asset.getIdentifier(), asset.getUsername(), myproxyPasswrod, lifetime, null);
		
		mp.setLifetime(lifetime * 1000);
		mp.doPut( assetResp.getX509Certificates() , asset.getPrivateKey());
		
	}

}
