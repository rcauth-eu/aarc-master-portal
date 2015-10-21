package org.masterportal.myproxy;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.globus.common.CoGProperties;
import org.globus.gsi.OpenSSLKey;
import org.globus.gsi.X509Credential;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;
import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import org.globus.gsi.gssapi.auth.IdentityAuthorization;
import org.globus.myproxy.CredentialInfo;
import org.globus.myproxy.GetParams;
import org.globus.myproxy.InfoParams;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxyException;
import org.globus.myproxy.StoreParams;
import org.globus.util.Util;
import org.gridforum.jgss.ExtendedGSSCredential;
import org.ietf.jgss.GSSCredential;
import org.masterportal.myproxy.exception.MyProxyCertExpiredExcpetion;
import org.masterportal.myproxy.exception.MyProxyNoUserException;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

public class MPCredStoreService {
	
	public static final String MYPROXY_SERVER_PORT = "7512";
    public static final int MYPROXY_DEFAULT_PROXY_LIFETIME = 12;
    public static final String MYPROXY_DEFAULT_PASSWORD = "changeit";
    
    private MyLoggingFacade logger = null;
    
	private CoGProperties properties = null;

	private Map<String,MPMyProxy> pendingSessions = null;
	
    private static MPCredStoreService instance = null;
	
    private MPCredStoreService() {
    	logger = new MyLoggingFacade(getClass().getName(), false);
    	properties = CoGProperties.getDefault();
    	pendingSessions = new HashMap<String,MPMyProxy>();
	}   

    public static MPCredStoreService getMPCredStoreService() {
    	if (instance == null) {
    		instance = new MPCredStoreService();
    	}
    	return instance;
    }
    
    
    public byte[] doPutStart(String identifier,String username) throws Exception {
    	
    	int lifetime = Integer.parseInt(properties.getProperty("lifetime"));
    	if (lifetime <= 0) {
    		lifetime =  MYPROXY_DEFAULT_PROXY_LIFETIME;
    	}
    	
        String password = properties.getProperty("password");
        if (password == null) {
        	password = MYPROXY_DEFAULT_PASSWORD;
        }
    	
    	logger.info("Starting PUT request for user " + username + " with id=" + identifier + "and lifetime=" + lifetime);

    	MPMyProxy myproxy = getMyProxy(identifier);

        // load default credentials to use for authentication with myproxy
        GSSCredential credential = getDefaultCredential();

        InitParams initRequest = new InitParams();
        initRequest.setUserName(username);
        initRequest.setLifetime(lifetime);
        initRequest.setPassphrase(password);
        
    	return myproxy.pput_start(credential, initRequest);
    }


	public void doPutFinish(String identifier,X509Certificate[] certificates) throws Exception {
    	
    	MPMyProxy myproxy = getMyProxy(identifier);
    	
    	myproxy.pput_finish(certificates);
    }
    
	
	public GlobusGSSCredentialImpl doGet(String username) throws Exception {
		
    	int lifetime = Integer.parseInt(properties.getProperty("lifetime"));
    	if (lifetime <= 0) {
    		lifetime =  MYPROXY_DEFAULT_PROXY_LIFETIME;
    	}
    	
        String password = properties.getProperty("password");
        if (password == null) {
        	password = MYPROXY_DEFAULT_PASSWORD;
        }
		
        GetParams getRequest = new GetParams();
        getRequest.setUserName(username);
        //getRequest.setCredentialName(credName);
        getRequest.setLifetime(lifetime);
        //getRequest.setWantTrustroots(true);
        /*if (! voname.isEmpty()) {
            getRequest.setVoname(voname);
            getRequest.setVomses( readVOMS_USERCONF() );
        }*/
        getRequest.setPassphrase(password);
        
        // load default credentials to use for authentication with myproxy
        GSSCredential credential = getDefaultCredential();
        
        MPMyProxy myproxy = getMyProxy();
        GSSCredential userCredentials = myproxy.get(credential, getRequest);
        
        /*
        byte [] data = ((ExtendedGSSCredential)userCredentials).export(ExtendedGSSCredential.IMPEXP_OPAQUE);
        
    	System.out.println("Exported CERT to IMPEXP_OPAQUE");
    	System.out.println("###########  CERT  ###########");
    	String csrString1 = new String(data);
    	System.out.println(csrString1);
    	System.out.println("###########  CERT  ###########");
        */
        
    	return ((GlobusGSSCredentialImpl)userCredentials);
    	
	}
	
    
    /*
     *  Execute a myproxy-store
     */
    public void doStore(String user, X509Certificate[] userCerts, PrivateKey userKey) throws Exception {
    	
        // set uploaded credential name 
        // equivalent of myproxy-store -k
        String credName = null;
        // set uploaded credential description 
        // equivalent of myproxy-store -K
        String credDesc = null;
        // maximum lifetime of proxies retrieved 
        // equivalent of myproxy-store -t
        int proxyLifetime = MYPROXY_DEFAULT_PROXY_LIFETIME * 3600;
        
        //the myproxy.store command expects a OpenSSLKey key instance
        //therefore we have to convert the key used by OA4MP
        OpenSSLKey userKeyGlobus = new BouncyCastleOpenSSLKey(userKey);

        logger.info("Building STORE request for " + user);
        logger.debug("user=" + user);
        logger.debug("proxy lifetime=" + proxyLifetime);
        logger.debug("credentail name=" + credName);
        
        // build store request
        StoreParams storeRequest = new StoreParams();
        storeRequest.setUserName(user);
        storeRequest.setLifetime(proxyLifetime);
        storeRequest.setCredentialName(credName);
        storeRequest.setCredentialDescription(credDesc);

        // load default credentials to use for authentication with myproxy
        GSSCredential credential = getDefaultCredential();
        
        logger.info("~ CERTs ~");
        for (X509Certificate cert : userCerts) {
        	System.out.print(cert.getEncoded());
        	logger.info("SUBJECT:" + cert.getSubjectDN());
        	logger.info("ISSUER:" + cert.getIssuerDN());
        }
        logger.info("~ END CERTs ~");        
        
        logger.info("~ KEY ~");
        System.out.println(userKey.getEncoded());        
        logger.info("~ END KEY ~");        

        logger.info("~ GLOBUS KEY ~");
        System.out.println(userKeyGlobus.getPrivateKey().getEncoded());
        logger.info("~ END GLOBUS KEY ~");                
        
        // send the store request
        MPMyProxy myProxy = getMyProxy();
        myProxy.store(credential, userCerts, userKeyGlobus, storeRequest);

    }
    
	/*
	 *  Execute a myproxy-info 
	 */
	public void doInfo(String username) throws Exception {
        
		// build info request
        InfoParams infoRequest = new InfoParams();
        infoRequest.setUserName(username);

        // load default credentials to use for authentication with myproxy
        GSSCredential credential = getDefaultCredential();
        
        // send the info request

        MPMyProxy myProxy = getMyProxy();
        CredentialInfo[] info = null;
        
        try {
        	info = myProxy.info(credential, infoRequest);
        } catch (MyProxyException e) {
        	if (e.getCause().getMessage().startsWith("no credentials found for use")) {
        		throw new MyProxyNoUserException("unknown user",e);
        	} else {
        		throw e;
        	}
        }
       
        // interpret results 
        // just print them out for now
        String tmp;
        System.out.println ("From MyProxy server: " + myProxy.getHost());
        System.out.println ("Owner: " + info[0].getOwner());
        
        for (int i=0;i<info.length;i++) {
            tmp = info[i].getName();
            System.out.println ((tmp == null) ? "default:" : tmp +":");
            System.out.println ("\tStart Time  : " +
                                info[i].getStartTime());
            System.out.println ("\tEnd Time    : " +
                                info[i].getEndTime());

            long now = System.currentTimeMillis();
            if (info[i].getEndTime() > now) {
                System.out.println ("\tTime left   : " +
                                    Util.formatTimeSec((info[i].getEndTime() - now)/1000));
            } else {
                System.out.println ("\tTime left   : expired");
            }

            tmp = info[i].getRetrievers();
            if (tmp != null) {
                System.out.println ("\tRetrievers  : "+tmp);
            }
            tmp = info[i].getRenewers();
            if (tmp != null) {
                System.out.println ("\tRenewers    : "+tmp);
            }
            tmp = info[i].getDescription();
            if (tmp != null) {
                System.out.println ("\tDescription : "+tmp);
            }
        } 
        
        if ( info.length > 1 ) {
        	throw new MyProxyException("Undefined behaviour! More then one certificate registered under username:" + username);
        }
        
        long now = System.currentTimeMillis();
        if (info[0].getEndTime() < now) {
        	throw new MyProxyCertExpiredExcpetion("User certificate expired in Credential Store!");
        }
	}
	
    /*
     *  Returns a MyProxy instance based on the current configuration
     */
	protected MPMyProxy getMyProxy() {
    
    	String hostname = properties.getProperty("hostname");
    	String port = properties.getProperty("port",MYPROXY_SERVER_PORT);
    	String myproxySubjectDN = properties.getProperty("myproxySubjectDN");
    	
    	logger.info("Creating MyProxy instance to " + hostname + ":" + port + " with DN=" + myproxySubjectDN);
    	
        MPMyProxy myProxy = new MPMyProxy(hostname, Integer.parseInt(port) );
        
        if (myproxySubjectDN != null) {
            myProxy.setAuthorization(new IdentityAuthorization(myproxySubjectDN));
        }

        return myProxy;
    }    	
    
    
	protected MPMyProxy getMyProxy(String identifier) {
    	
    	MPMyProxy myProxy = null;
    	
    	if ( pendingSessions.containsKey(identifier) ) {
    		myProxy = pendingSessions.get(identifier);
    	} else {
    		myProxy = getMyProxy();
			pendingSessions.put(identifier, myProxy);
    	}
    	
		return myProxy;
	}    
    
	
    /*
     *  Returns a GSSCredential created from the hostcert and hostkey 
     */
	protected GSSCredential getDefaultCredential() throws Exception {
    	
        String hostCertFile = properties.getProperty("hostcert");
        String hostKeyFile = properties.getProperty("hostkey");
		
        logger.info("Loading host certificates from " + hostCertFile );
        logger.info("Loading host key from " + hostKeyFile);
        
		X509Credential hostcred = new X509Credential(hostCertFile, hostKeyFile);
		
		GSSCredential credential = new GlobusGSSCredentialImpl(hostcred,
															   GSSCredential.INITIATE_ONLY);
		return credential;
    }

}
