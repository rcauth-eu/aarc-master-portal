package org.masterportal.server.oauth2.servlet;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import org.masterportal.myproxy.CredStoreService;
import org.masterportal.myproxy.exception.MyProxyCertExpiredExcpetion;
import org.masterportal.myproxy.exception.MyProxyNoUserException;
import org.masterportal.myproxy.jglobus.JGlobusCredStoreService;
import org.masterportal.myproxy.jglobus.MPCredStoreService;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2CertServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.token.MyX509Proxy;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;

public class MPOA2ProxyServlet extends OA2CertServlet {

	@Override
	public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
		ServiceTransaction transaction = super.verifyAndGet(iResponse);
		
		// insert a CSR into the transaction
		KeyPair keyPair = null;
		MyPKCS10CertRequest certReq = null;
        try {
        	keyPair = KeyUtil.generateKeyPair();
            certReq = CertUtil.createCertRequest(keyPair, "");
        } catch (Throwable e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new GeneralException("Could no create cert request", e);
        }
		transaction.setCertReq(certReq);
		
		return transaction;
	}

	
	@Override
	protected void doRealCertRequest(ServiceTransaction trans, String statusString) throws Throwable {
		
		String username = trans.getUsername();
		
		// use jglobus myproxy to connect to the CredStore and retrieve a proxy
		
	    CredStoreService credStore = JGlobusCredStoreService.getInstance();
        boolean userCertValid = false;
        
        try {    	    
    	    info("Executing MyProxy INFO with username : " + username);
        	credStore.doInfo(username);
        	debug("Valid user certificate found!");
        	userCertValid = true;
        } catch (MyProxyNoUserException e) {
        	debug("No user found in MyProxy Credential Store!");
        	userCertValid = false;
        } catch (MyProxyCertExpiredExcpetion e) {
        	debug("User certificate from MyProxy Credential Store is expired!");
        	userCertValid = false;
        }
        
    
        if (!userCertValid) {
        	
        	info("2.a. Proxy retrieval failed! Creating new user certificate ...");
        	// call /forwardetproxy on the Master Portal Client component
        	
        }
        
    	info("2.a.1 Trying to create proxy certificate for user");
    	//TODO: voms_fqan goes here as 2nd parameter
    	byte[] userProxy = credStore.doGet(username, null);
		
		// create MyX509Proxy to return
    	MyX509Proxy proxy = new MyX509Proxy(userProxy);
		
    	// save proxy as ProtectedAsset into trans
    	trans.setProtectedAsset(proxy);
    	getServiceEnvironment().getTransactionStore().save(trans);
	}
	

}
