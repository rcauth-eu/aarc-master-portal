package org.masterportal.myproxy.jglobus;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.PropertyConfigurator;
import org.globus.common.CoGProperties;
import org.globus.gsi.X509Credential;
import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import org.globus.gsi.gssapi.auth.IdentityAuthorization;
import org.globus.myproxy.CredentialInfo;
import org.globus.myproxy.GetParams;
import org.globus.myproxy.InfoParams;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxyException;
import org.globus.util.Util;
import org.gridforum.jgss.ExtendedGSSCredential;
import org.ietf.jgss.GSSCredential;
import org.masterportal.myproxy.exception.MyProxyCertExpiredExcpetion;
import org.masterportal.myproxy.exception.MyProxyNoUserException;

public class MPCredStoreService {
	
	public static final String MYPROXY_SERVER_PORT = "7512";
    public static final int MYPROXY_DEFAULT_PROXY_LIFETIME = 43200;
    public static final String MYPROXY_DEFAULT_PASSWORD = "changeit";
    
    public static final String MP_OA2_MYPROXY_CONFIG_LOG4J = "org.globus.log4j.properties";
    
    private Log logger = null;
    
	private CoGProperties properties = null;

	private Map<String,MPMyProxy> pendingSessions = null;
	
    private static MPCredStoreService instance = null;
	
    private MPCredStoreService() {
    	String logProperties = System.getProperty(MP_OA2_MYPROXY_CONFIG_LOG4J);
    	if (logProperties != null && !logProperties.isEmpty()) {
    		PropertyConfigurator.configure(logProperties);
        }
    	logger = LogFactory.getLog(this.getClass());
        properties = CoGProperties.getDefault();
    	pendingSessions = new HashMap<String,MPMyProxy>();
	}   
    
    
    public static MPCredStoreService getMPCredStoreService() {
    	if (instance == null) {
    		instance = new MPCredStoreService();
    	}
    	return instance;
    }
    
    /*
     *  Execute the first half of the PUT protocol and save the session
     */
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
        
        logger.info("Pending PUT request waiting for completion ...");
        
    	return myproxy.pput_start(credential, initRequest);
    }

    /* 
     *  Execute the second half of the PUT protocol by retrieving a previously saved session
     */
	public void doPutFinish(String identifier,X509Certificate[] certificates) throws Exception {
    	
		logger.info("Finishing PUT request with id=" + identifier);
		
    	MPMyProxy myproxy = getMyProxy(identifier);
    	
    	myproxy.pput_finish(certificates);
    }
    
	/*
	 *  Execute a MyProxy GET command
	 */
	public GlobusGSSCredentialImpl doGet(String username, String voms_fqan) throws Exception {
		
		
    	int lifetime = Integer.parseInt(properties.getProperty("lifetime"));
    	if (lifetime <= 0) {
    		lifetime =  MYPROXY_DEFAULT_PROXY_LIFETIME;
    	}
    	
        String password = properties.getProperty("password");
        if (password == null) {
        	password = MYPROXY_DEFAULT_PASSWORD;
        }
		
        logger.info("Starting GET request for user " + username + " and lifetime=" + lifetime + " and voms=" + voms_fqan);
    	
        GetParams getRequest = new GetParams();
        getRequest.setUserName(username);
        getRequest.setLifetime(lifetime);
        if ( voms_fqan != null ) {
        	
        	// we might have to add then one by one instead of all on one line...
        	ArrayList<String> voms_array = new ArrayList<String>();
        	voms_array.add(voms_fqan);
            getRequest.setVoname(voms_array);
            
        }
        getRequest.setPassphrase(password);
        
        // load default credentials to use for authentication with myproxy
        GSSCredential credential = getDefaultCredential();
        
        MPMyProxy myproxy = getMyProxy();
        GSSCredential userCredentials = null;
        
        userCredentials = myproxy.get(credential, getRequest);
        
        
        byte [] data = ((ExtendedGSSCredential)userCredentials).export(ExtendedGSSCredential.IMPEXP_OPAQUE);
    	logger.debug("Exported CERT to IMPEXP_OPAQUE");
    	logger.debug("###########  CERT  ###########");
    	logger.debug(new String(data));
    	logger.debug("###########  CERT  ###########");
        
        
    	return ((GlobusGSSCredentialImpl)userCredentials);
    	
	}
	
    
	/*
	 *  Execute a MyProxy INFO command
	 */
	public void doInfo(String username) throws Exception {
        
		logger.info("Starting an INFO request for username " + username);
		
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
        	if (e.getCause().getMessage().startsWith("no credentials found for user")) {
        		logger.warn("No credentials found for user!");
        		throw new MyProxyNoUserException("unknown user",e);
        	} else {
        		throw e;
        	}
        }
       
        // interpret results 
        // just print them out for now
        String tmp;
        logger.info("Owner: " + info[0].getOwner());
        
        for (int i=0;i<info.length;i++) {
            tmp = info[i].getName();
            logger.info((tmp == null) ? "default:" : tmp +":");
            logger.info("\tStart Time  : " + info[i].getStartTime());
            logger.info("\tEnd Time    : " + info[i].getEndTime());

            long now = System.currentTimeMillis();
            if (info[i].getEndTime() > now) {
            	logger.info("\tTime left   : " +
                                    Util.formatTimeSec((info[i].getEndTime() - now)/1000));
            } else {
            	logger.info("\tTime left   : expired");
            }

            tmp = info[i].getRetrievers();
            if (tmp != null) {
            	logger.info("\tRetrievers  : "+tmp);
            }
            tmp = info[i].getRenewers();
            if (tmp != null) {
            	logger.info("\tRenewers    : "+tmp);
            }
            tmp = info[i].getDescription();
            if (tmp != null) {
            	logger.info("\tDescription : "+tmp);
            }
        } 
        
        if ( info.length > 1 ) {
        	logger.error("More than one certificate found unser one username!");
        	throw new MyProxyException("Undefined behaviour! More then one certificate registered under username:" + username);
        }
        
        long now = System.currentTimeMillis();
        if (info[0].getEndTime() < now) {
        	logger.warn("User credentials expired!");
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
    
    /*
     *  The MyProxy PUT request is redesigned to work together with the
     *  OA4MP /getCert endpoint. This forces the PUT request to hang in the
     *  middle and wait for a valid certificate to be returned. This method 
     *  is used to save pending MyProxy sessions 
     */
	protected MPMyProxy getMyProxy(String identifier) {
    	
    	MPMyProxy myProxy = null;
    	
    	if ( pendingSessions.containsKey(identifier) ) {
    		myProxy = pendingSessions.get(identifier);
    		//TODO Maybe remove it from the pending sessions once it's retrieved...
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
