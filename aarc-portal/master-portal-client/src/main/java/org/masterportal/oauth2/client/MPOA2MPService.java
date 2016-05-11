package org.masterportal.oauth2.client;

import java.security.GeneralSecurityException;
import java.util.Map;

import edu.uiuc.ncsa.myproxy.MPConnectionProvider;
import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.util.pkcs.ProxyUtil;

public class MPOA2MPService extends OA2MPService {

	/* SERVICE LOADER */
	
	public static class MPOA2MPProvider extends OA4MPServiceProvider {
		public MPOA2MPProvider(ClientEnvironment clientEnvironment) {
			super(clientEnvironment);
		}

		@Override
		public MPOA2MPService get() {
			return new MPOA2MPService(clientEnvironment);
		}
	}

	/* CONSTRUCTOR */
	
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
	
	/* OVERRIDEN METHODS */
	
	/**
	 *  Extended /getcert request. This executes the regular /getcert request (just as
	 *  the normal OA4MP Client would) but instead of passing the resulting credential,
	 *  instead it stores it in the form of a long lived proxy certificate.
	 *  <p> 
	 *  This method accounts for checking whether the retrieved credential is an 
	 *  EEC or a Proxy. In case of an EEC a proxy is created via the MyProxy PUT command.
	 *  In case of the Proxy the MyProxy STORE command is used instead.
	 * 
	 */
	@Override
	public AssetResponse getCert(OA2Asset a, ATResponse2 atResponse2) {
		AssetResponse par = super.getCert(a, atResponse2);

		logger.debug("Certificate request ended, trying to store the received cert in the Credential Store");

		try {
		
			// see if the result is a proxy or an EEC
			if ( ProxyUtil.isProxy(par.getX509Certificates()) ) {
	
				logger.debug("Using MyProxy STORE to store credential");
				// Proxy Certificate use STORE
				storeProxy(par,a);
	
			} else {
	
				logger.debug("Using MyProxy PUT to store credential");
				// User EE Certificate use PUT
				putCert(par,a);
				
			}
	
			return par;
		
		} catch (Throwable e) {
			if (e instanceof GeneralException) {
				throw (GeneralException) e;
			} else {
				throw new GeneralException(e);
			}
		}
	}

	/**
	 * This extended method makes sure that the SCOPE parameter 
	 * provided in the parameter map is not getting overwritten 
	 * by any subsequent pre-processing.
	 * <p>
	 * This method will only have effect if the provided parameter 
	 * map has its SCOPE parameter set before this method is called.
	 * 
	 * @param asset The current session asset
	 * @param parameters The parameter map that will end up in the authorize request 
	 */
	@Override
	public void preRequestCert(Asset asset, Map parameters) {
	
		if ( parameters.get(OA2Constants.SCOPE) != null ) {
			// save original SCOPE parameter
			String originalScopes = (String) parameters.get(OA2Constants.SCOPE);
			
			super.preRequestCert(asset, parameters);
			
			// make sure the original SCOPE parameter is set
			parameters.put(OA2Constants.SCOPE, originalScopes);
		}
	}
	
	/* MYPROXY COMMANDS */

	/**
	 * Use MyProxy PUT command to store a Long Lived Proxy certificate made from the 
	 * EEC found in the assetResp. Call this in case /getcert returns an EEC.
	 * 
	 * @param assetResp The asset response of a /getcert request
	 * @param asset The asset created to identify the ongoing session
	 * @throws Throwable MyProxy related exceptions 
	 */
	public void putCert(AssetResponse assetResp, OA2Asset asset) throws Throwable {

		String myproxyPasswrod  = ((MPOA2ClientEnvironment)getEnvironment()).getMyproxyPassword();
		long lifetime = getEnvironment().getCertLifetime();
		
		MyProxyConnectable mp = createMPConnection(asset.getIdentifier(), asset.getUsername(), myproxyPasswrod, lifetime);
		
		mp.setLifetime(lifetime * 1000);
		mp.doPut( assetResp.getX509Certificates() , asset.getPrivateKey());
		
	}

	/**
	 * Use MyProxy STORE command to store the Proxy certificate found in the assetResp. 
	 * Call this in case /getcert returns a Proxy.  
	 * 
	 * @param assetResp The asset response of a /getcert request
	 * @param asset The asset created to identify the ongoing session
	 * @throws Throwable MyProxy related exceptions 
	 */
	public void storeProxy(AssetResponse assetResp, OA2Asset asset) throws Throwable {

		String myproxyPasswrod  = ((MPOA2ClientEnvironment)getEnvironment()).getMyproxyPassword();
		long lifetime = getEnvironment().getCertLifetime();
		
		MyProxyConnectable mp = createMPConnection(asset.getIdentifier(), asset.getUsername(), myproxyPasswrod, lifetime);
		
		mp.setLifetime(lifetime * 1000);
		mp.doStore( assetResp.getX509Certificates() , asset.getPrivateKey());
		
	}	

	/* HELPER METHODS */

	/**
	 * Create a connection to a MyProxy Server. This method uses the MyProxy Server 
	 * connection configuration, and is written after the MyProxy Connection model 
	 * in the OA4MP Server component. 
	 * 
	 * @param identifier The asset(session) identifier to identify the connection by 
	 * @param userName The username used in the MyProxy connection
	 * @param password The password used in the MyProxy connection
	 * @param lifetime The lifetime used in the MyProxy connection
	 * @return The established MyProxy connection
	 * @throws GeneralSecurityException In case a connection could not be established.
	 */
	protected MyProxyConnectable createMPConnection(Identifier identifier, String userName, String password,
			long lifetime) throws GeneralSecurityException {
		
		MPConnectionProvider facades = new MPConnectionProvider(logger, 
																((MPOA2ClientEnvironment)getEnvironment()).getMyProxyServices() );
		// use null for the LOA since we are not supporting any at the moment
		MyProxyConnectable mpc = facades.findConnection(identifier, userName, password, null, lifetime);
		return mpc;
	}
	
}
