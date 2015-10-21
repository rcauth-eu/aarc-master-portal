package org.masterportal.oauth2.client;

import java.security.cert.X509Certificate;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.globus.myproxy.CredentialInfo;
import org.masterportal.myproxy.MPCredStoreService;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.client.request.DelegatedAssetResponse;
import edu.uiuc.ncsa.security.delegation.token.MyX509Certificates;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;


/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/21/15 at  12:03 PM
 */
public class MPOA2MPService extends OA2MPService {
    public static class MPOA2MPProvider extends OA4MPServiceProvider{
        public MPOA2MPProvider(ClientEnvironment clientEnvironment) {
            super(clientEnvironment);
        }

        @Override
        public MPOA2MPService get() {
            return new MPOA2MPService(clientEnvironment);
        }
    }

    public MPOA2MPService(ClientEnvironment environment) {
        super(environment);
    }
    
    @Override
    public void preRequestCert(Asset asset, Map parameters) {
    	super.preRequestCert(asset, parameters);
    	
    	// tweaking the PROMPT parameter
    	
    	//getLogger().info("Entering RequestCert Postprocessing");
    	//getLogger().info("old prompt : " + parameters.get(OA2Constants.PROMPT));
    	//parameters.remove(OA2Constants.PROMPT);
    	//parameters.put(OA2Constants.PROMPT, OA2Constants.PROMPT_NONE);
    	//getLogger().info("new prompt : " + parameters.get(OA2Constants.PROMPT));
    	//getLogger().info("Exiting RequestCert Postprocessing");
    }
    
    @Override
    public AssetResponse getCert(OA2Asset a, ATResponse2 atResponse2) {

        Map<String, String> m1 = getAssetParameters(a);
        preGetCert(a, m1);
        
        DelegatedAssetResponse daResp = getEnvironment().getDelegationService().getCert(atResponse2, getEnvironment().getClient(), m1);

        AssetResponse par = new AssetResponse();
        MyX509Certificates myX509Certificate = (MyX509Certificates) daResp.getProtectedAsset();
        par.setX509Certificates(myX509Certificate.getX509Certificates());
        // OAuth 2/OIDC returns this with the access token.
        //par.setUsername(daResp.getAdditionalInformation().get("username"));
        postGetCert(a, par);
        a.setCertificates(par.getX509Certificates());
        getEnvironment().getAssetStore().save(a);
        return par;
    }
    
    
    @Override
    public void preGetCert(Asset asset, Map parameters) {
    	
    	getLogger().info("Entering Master Portal GetCert Preprocessing");
    	
    	MyPKCS10CertRequest certReq = null;
    	try {
        
        	MPCredStoreService credStore = MPCredStoreService.getMPCredStoreService();
        	byte[] csr = credStore.doPutStart(asset.getIdentifierString(), asset.getUsername());

        	System.out.println("Starting /getCert request with CSR");
        	System.out.println("###########  CSR  ###########");
        	String csrString = new String(Base64.encodeBase64(csr));
        	System.out.println(csrString);
        	System.out.println("###########  CSR  ###########");        	
        	
        	certReq = CertUtil.fromStringToCertReq(csrString); 
        	
		} catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new GeneralException("Error getting CSR from MyProxy Credential Store", e);
		}
        
    	// we don't have a private key at the master portal anymore, therefore nothing to store
        //a.setPrivateKey(keyPair.getPrivate());
    	asset.setCertReq(certReq);    	
    	
    	getLogger().info("Exiting Master Portal GetCert Preprocessing");
    	
    	super.preGetCert(asset, parameters);
    }
    
    @Override
    public void postGetCert(Asset asset, AssetResponse assetResponse) {
    	
    	getLogger().info("Entering Master Portal GetCert Postprocessing");
    	
    	X509Certificate[] certs = assetResponse.getX509Certificates();
    	getLogger().info("Nr of certificates found: " + certs.length);
    	
        X509Certificate userCert = null;
        if (certs.length != 0) {
            userCert = certs[0];
        	if (certs.length > 1) {
	                getLogger().info("Why are there " + certs.length + " certs ?");
	        }
        } else {
        	throw new GeneralException("No certificate returned for post processing!");
        }

    	getLogger().info("Got cert with DN: " + userCert.getSubjectDN());

    	try {
        	System.out.println("Ending /getCert request with Cert");
        	System.out.println("###########  CERT  ###########");
        	String c = new String(Base64.encodeBase64(userCert.getEncoded()));
        	System.out.println(c);
            System.out.println("###########  CERT  ###########"); 
            
        	MPCredStoreService credStore = MPCredStoreService.getMPCredStoreService();
        	credStore.doPutFinish(asset.getIdentifierString(),certs);
        	
		} catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new GeneralException("Error storing the certificate to MyProxy Credential Store", e);
		}    	
    	

    	getLogger().info("Exiting Master Portal GetCert Postprocessing");
    	
    	super.postGetCert(asset, assetResponse);
    }
    
    protected MyLoggingFacade getLogger() {
        if (getEnvironment() != null) {
            return getEnvironment().getMyLogger();
        }
        // always return one so even if things blow up some record remains...
        return new MyLoggingFacade("oa4mp");
    }        

}
