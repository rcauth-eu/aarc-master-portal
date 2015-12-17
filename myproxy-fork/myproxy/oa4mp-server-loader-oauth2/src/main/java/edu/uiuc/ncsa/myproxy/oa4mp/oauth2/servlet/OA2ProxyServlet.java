package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.Map;

import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2CertServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.token.MyX509Certificates;
import edu.uiuc.ncsa.security.delegation.token.MyX509Proxy;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;

/**
 * Implementation of /getproxy Servlet. This servlet will create a keypair, send the CSR
 * along to MyProxy just like you would in case of /getcert. Before returning the resulting
 * certificates to the requester, it inserts the private key into the response
 * 
 * <p>Created by Tamas Balogh</p>
 *
 */
public class OA2ProxyServlet extends OA2CertServlet {
	
	@Override
	public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
	
		OA2ServiceTransaction trans = (OA2ServiceTransaction) super.verifyAndGet(iResponse);
		
		debug("6.a. Generating keypair for proxy creation");
		// create keypair
		KeyPair keyPair = null;
		MyPKCS10CertRequest certReq = null;
        try {
        	keyPair = KeyUtil.generateKeyPair();
            certReq = CertUtil.createCertRequest(keyPair, trans.getUsername());
        } catch (Throwable e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new GeneralException("Could no create cert request", e);
        }
        
        // insert a CSR and generated keypair into the transaction 
        trans.setCertReq(certReq);
        trans.setKeypair(keyPair);
		
		Map params = iResponse.getParameters();
		
		// for some reason lifetime is kept in the system as milisec, but sent to MyProxy in sec (correctly)
		// why bother with this conversion and just keep lifetime in sec in the system instead of milisec ?
        if(params.containsKey(OA2Constants.PROXY_LIFETIME)) {
        	trans.setLifetime(1000 * Long.parseLong(((String) params.get(OA2Constants.PROXY_LIFETIME))));
        	debug("6.a. Setting proxy lifetime for request value " + OA2Constants.PROXY_LIFETIME + "=" + trans.getLifetime());
        }else{
        	trans.setLifetime(1000 * 10*24*3600); // set the default to 10 days if there is no certlifetime parameter passed in.
        	debug("6.a. Setting proxy lifetime for default value = " + trans.getLifetime());
        }			
        
		
		if (params.containsKey(OA2Constants.VONAME)) {
			trans.setVoname( String.valueOf(params.get(OA2Constants.VONAME)) );	
			debug("6.a. VONAME = " + trans.getVoname() + " will be requested for the proxy");
		}
		
		if (params.containsKey(OA2Constants.VOMSES)) {
			trans.setVomses( String.valueOf(params.get(OA2Constants.VOMSES)) );
			debug("6.a. VOMSES = " + trans.getVomses() + " will get contacted for the proxy");			
		}
		
		return trans;
	}
	
	@Override
	protected void checkMPConnection(OA2ServiceTransaction st) throws GeneralSecurityException {
        if (!hasMPConnection(st)) {
        	// the password here is unset. override this method if you need to set a password here
        	debug("Creting new MP connection with username: " + st.getUsername() + " and lifetime: " + st.getLifetime());
            createMPConnection(st.getIdentifier(), st.getUsername(), "", st.getLifetime());
        }
	}
	
	@Override
	public void preprocess(TransactionState state) throws Throwable {
		super.preprocess(state);
		
		//swap out MyX509Certificates for a MyX509Proxy
		MyX509Certificates certs =  (MyX509Certificates) state.getTransaction().getProtectedAsset();
		KeyPair keyPair  = ((OA2ServiceTransaction)state.getTransaction()).getKeypair();
		
		MyX509Proxy proxy = new MyX509Proxy(certs, keyPair.getPrivate());
			
		state.getTransaction().setProtectedAsset(proxy);
	}	
	
	@Override
	protected LinkedList<X509Certificate> getX509Certificates(ServiceTransaction transaction,
			MyPKCS10CertRequest localCertRequest, String statusString) throws GeneralSecurityException {
		
        MyProxyConnectable mpc = getMPConnection(transaction);
        mpc.setLifetime(transaction.getLifetime());

		OA2ServiceTransaction trans =  (OA2ServiceTransaction) transaction;
		mpc.setVoname(trans.getVoname());
		mpc.setVomses(trans.getVomses());
		
        LinkedList<X509Certificate> certs = mpc.getCerts(localCertRequest);

        if (certs.isEmpty()) {
            info(statusString + "Error: MyProxy service returned no certs.");
            throw new GeneralException("Error: MyProxy service returned no certs.");
        }

        info(statusString + "Got cert from MyProxy");
        return certs;
        
	}
	
}
