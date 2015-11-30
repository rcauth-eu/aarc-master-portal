package org.masterportal.server.oauth2.servlet;

import java.io.IOException;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.masterportal.myproxy.CredStoreService;
import org.masterportal.myproxy.exception.MyProxyCertExpiredExcpetion;
import org.masterportal.myproxy.exception.MyProxyNoUserException;
import org.masterportal.myproxy.jglobus.JGlobusCredStoreService;
import org.masterportal.server.oauth2.MPOA2SE;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2CertServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.server.request.PPRequest;
import edu.uiuc.ncsa.security.delegation.server.request.PPResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.token.MyX509Proxy;
import edu.uiuc.ncsa.security.oauth_2_0.ProxyOA2Constants;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;

public class MPOA2ProxyServlet extends OA2CertServlet {

	@Override
	public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
		ServiceTransaction transaction = super.verifyAndGet(iResponse);
		
		// insert a CSR into the transaction
		/*
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
		*/
		
		return transaction;
	}

	
	@Override
	protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
		
        info("6.a. Starting to process proxy request");
        PPRequest ppRequest = new PPRequest(httpServletRequest, getClient(httpServletRequest));
        String statusString = "client = " + ppRequest.getClient().getIdentifier();
        // The next call will pull the access token off of any parameters. The result may be null if there is
        // no access token.
        ppRequest.setAccessToken(getAccessToken(httpServletRequest));

        PPResponse ppResponse = (PPResponse) getPPI().process(ppRequest);
        
        debug("6.a. " + statusString);
        ServiceTransaction t = verifyAndGet(ppResponse);
        Map params = httpServletRequest.getParameterMap();

        
        if(params.containsKey(ProxyOA2Constants.PROXY_LIFETIME)) {
            t.setLifetime(Long.parseLong(((String[]) params.get(ProxyOA2Constants.PROXY_LIFETIME))[0]));
        	debug("6.a. Setting proxy lifetime from request value " + ProxyOA2Constants.PROXY_LIFETIME + "=" + t.getLifetime());
        }else{
        	t.setLifetime(10*24*3600); // set the default to 10 days if there is no certlifetime parameter passed in.
        	debug("6.a. Setting proxy lifetime from default value = " + t.getLifetime());
        }
        
        
        info("6.a. Processing request for transaction " + t.getIdentifier());
        doRealProxyRequest(t, 
        				   statusString, 
        				   httpServletRequest.getParameter(ProxyOA2Constants.VOMS_FQAN));
        t.setAccessTokenValid(false);
        preprocess(new TransactionState(httpServletRequest, httpServletResponse, ppResponse.getParameters(), t));

        debug("6.a. protected asset:" + (t.getProtectedAsset() == null ? "(null)" : "ok") + ", " + statusString);
        HashMap<String, String> username = new HashMap<String, String>();
        username.put("username", t.getUsername());
        if (ppResponse.getParameters() != null) {
            username.putAll(ppResponse.getParameters());
        }
        ppResponse.setAdditionalInformation(username);
        ppResponse.setProtectedAsset(t.getProtectedAsset());
        debug("6.a. Added username \"" + t.getUsername() + "\" & cert for request from " + statusString);
        getTransactionStore().save(t);

        info("6.b. Done with proxy request " + statusString);
        ppResponse.write(httpServletResponse);
        info("6.b. Completed transaction " + t.getIdentifierString() + ", " + statusString);
        postprocess(new TransactionState(httpServletRequest, httpServletResponse, ppResponse.getParameters(), t));		
		
	}
	
	protected void doRealProxyRequest(ServiceTransaction trans, String statusString, String voms_fqan) throws Throwable {
		
		String username = trans.getUsername();
		long proxyLifetime = trans.getLifetime();
		
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
    	byte[] userProxy = credStore.doGet(username, (int) proxyLifetime, voms_fqan);
		
		// create MyX509Proxy to return
    	MyX509Proxy proxy = new MyX509Proxy(userProxy);
		
    	// save proxy as ProtectedAsset into trans
    	trans.setProtectedAsset(proxy);
    	getServiceEnvironment().getTransactionStore().save(trans);
	}
	
	
    protected PAIssuer getPPI() throws IOException {
        return ((MPOA2SE)getServiceEnvironment()).getPpIssuer();
    }

}
