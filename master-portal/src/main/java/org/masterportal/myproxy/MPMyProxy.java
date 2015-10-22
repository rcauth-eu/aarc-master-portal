package org.masterportal.myproxy;


import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.globus.gsi.gssapi.net.GssSocket;
import org.globus.gsi.util.CertificateUtil;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.X509Name;
import org.globus.gsi.X509Credential;
import org.globus.gsi.bc.BouncyCastleCertProcessingFactory;
import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import org.globus.myproxy.GetParams;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxyConstants;
import org.globus.myproxy.MyProxyException;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.masterportal.myproxy.exception.MyProxyVomsException;

public class MPMyProxy extends org.masterportal.myproxy.MyProxy {

    static Log logger = LogFactory.getLog(MyProxy.class.getName());	
    
    private Socket pendingGSISocket = null;
    private OutputStream pendingOUT = null;
    private InputStream  pendingIN  = null;
	
	public MPMyProxy(String host, int port) {
		super(host,port);
	}
	
	public MPMyProxy() {
		super();
	}
	
	/*
	 *  First Phase of PUT COMMAND
	 *  
	 *  It sets up connection with MyProxy Server and returns the CSR returned from it. 
	 *  The connection is saved as 'pending' and it is expected to be finished by calling
	 *  pput_finish(). 
	 */
    public byte[] pput_start(GSSCredential credential, InitParams params) throws MyProxyException {
    	
    	logger.debug("<<<< Starting pending put request >>>>");
    	
    	//we should make sure that any previous pending connection is closed first here!!
    	if ( pendingGSISocket != null || pendingIN != null || pendingOUT != null) {
    		
    		try {
    			close(pendingOUT, pendingIN, pendingGSISocket);
    			
    			logger.debug("trying to close pending session...");
    		} catch (Exception e) {
    			//oh well
    		}
    		
            pendingGSISocket = null;
            pendingOUT = null;
            pendingIN  = null;
    		
    	}   	
    	
        if (credential == null) {
            throw new IllegalArgumentException("credential == null");
        }

        if (params == null) {
            throw new IllegalArgumentException("params == null");
        }

        if (!(credential instanceof GlobusGSSCredentialImpl)) {
            throw new IllegalArgumentException("wrong type of credentials");
        }

        String msg = params.makeRequest();

        Socket gsiSocket = null;
        OutputStream out = null;
        InputStream  in  = null;

        try {
        	logger.debug("openning socket");
        	gsiSocket = getSocket(credential);

            out = gsiSocket.getOutputStream();
            in  = gsiSocket.getInputStream();
            
        	logger.debug("saving pending connection");
        	
            pendingGSISocket = gsiSocket;
            pendingOUT = out;
            pendingIN  = in;

            if (!((GssSocket)gsiSocket).getContext().getConfState())
                throw new Exception("Confidentiality requested but not available");

            // send message
        	logger.debug("initializing connection");
            out.write(msg.getBytes());
            out.flush();

        	logger.debug("handling response");
            handleReply(in);


            // do not close this here because it breaks the connection
            ASN1InputStream derin = new ASN1InputStream(in);
            ASN1Primitive reqInfo = (ASN1Primitive) derin.readObject();
            
            byte [] b = reqInfo.getEncoded();
            
        	logger.debug("returning certificate request with length " + b.length);
        	
        	logger.debug("<<<< Ending pending put request >>>>");
        	
            return b;
            
        } catch(Exception e) {
            
            // close socket
            close(pendingOUT, pendingIN, pendingGSISocket);
            
            pendingGSISocket = null;
            pendingOUT = null;
            pendingIN  = null;
            
            throw new MyProxyException("MyProxy put failed.", e);
        }
        
        
    }

	/*
	 *  Second Phase of PUT COMMAND
	 *  
	 *  It expects a signed certificate corresponding the the CSR returned by pput_start()
	 *  This certificate is then send over the pending MyProxy connection in order to 
	 *  finish the PUT command
	 */
    public void pput_finish(X509Certificate[] certificates) throws MyProxyException {
    	
    	if ( pendingGSISocket == null || pendingIN == null || pendingOUT == null) {
    		
            pendingGSISocket = null;
            pendingOUT = null;
            pendingIN  = null;
    		
    		throw new MyProxyException("Pending MyProxy connection not found!");
    	}
    	
        try {	    	
	        
	        // must put everything into one message
	        ByteArrayOutputStream buffer = new ByteArrayOutputStream(2048);
	
	        buffer.write( (byte)(certificates.length) );
	
	        // write signed certificates
	        for (int i=0;i<certificates.length;i++) {
	            buffer.write( certificates[i].getEncoded() );
	            logger.debug("Sent cert: " + certificates[i].getSubjectDN());		
	        }
	
	        pendingOUT.write(buffer.toByteArray());
	        pendingOUT.flush();
	
	        handleReply(pendingIN);
	
	    } catch(Exception e) {
	        throw new MyProxyException("MyProxy put failed.", e);
	    } finally {
            // close socket
            close(pendingOUT, pendingIN, pendingGSISocket);
            
            pendingGSISocket = null;
            pendingOUT = null;
            pendingIN  = null;
	    }    	
    	
    }
    
    
    @Override
    public GSSCredential get(GSSCredential credential, GetParams params) throws MyProxyException {
    
        if (params == null) {
            throw new IllegalArgumentException("params == null");
        }

        if (credential == null) {
            try {
                credential = getAnonymousCredential();
            } catch (GSSException e) {
                throw new MyProxyException("Failed to create anonymous credentials", e);
            }
        }

        String msg = params.makeRequest();

        Socket gsiSocket = null;
        OutputStream out = null;
        InputStream in   = null;

        try {
            gsiSocket = getSocket(credential);

            if (credential.getName().isAnonymous()) {
                this.context.requestAnonymity(true);
            }

            out = gsiSocket.getOutputStream();
            in  = gsiSocket.getInputStream();

            if (!((GssSocket)gsiSocket).getContext().getConfState())
                throw new Exception("Confidentiality requested but not available");

            // send message
            out.write(msg.getBytes());
            out.flush();

            if (logger.isDebugEnabled()) {
                logger.debug("Req sent:" + params);
            }

            // may require authz handshake
            handleReply(in, out, params.getAuthzCreds(),
                        params.getWantTrustroots());

            // start delegation - generate key pair
            KeyPair keyPair = CertificateUtil.generateKeyPair("RSA",
                    DEFAULT_KEYBITS);

            // According to the MyProxy protocol, the MyProxy server
            // will ignore the subject in the client's certificate
            // signing request (CSR). However, in some cases it is
            // helpful to control the CSR subject (for example, when
            // the MyProxy server is using a CA back-end that can only
            // issue certificates with subjects matching the request).
            // So we construct the CSR subject using the given MyProxy
            // username (if possible).
            String CSRsubjectString = params.getUserName();
            CSRsubjectString = CSRsubjectString.trim();
            if (CSRsubjectString.contains("CN=") ||
                CSRsubjectString.contains("cn=")) {
                // If the MyProxy username is a DN, use it.
                if (CSRsubjectString.charAt(0) == '/') {
                    // "good enough" conversion of OpenSSL DN strings
                    CSRsubjectString = CSRsubjectString.substring(1);
                    CSRsubjectString = CSRsubjectString.replace('/', ',');
                }
            } else {
                CSRsubjectString = "CN="+CSRsubjectString;
            }

            X509Name CSRsubjectName;
            try {
                CSRsubjectName = new X509Name(CSRsubjectString);
            } catch (Exception e) {
                // If our X509Name construction fails for any reason,
                // just use a default value (as in the past).
                CSRsubjectName = new X509Name("CN=ignore");
            }

            if (logger.isDebugEnabled()) {
                logger.debug("CSR subject: " + CSRsubjectName.toString());
            }

            BouncyCastleCertProcessingFactory certFactory =
                BouncyCastleCertProcessingFactory.getDefault();

            byte [] req = null;
            req = certFactory.createCertificateRequest(CSRsubjectName,
                                                       "SHA1WithRSAEncryption",
                                                       keyPair);

            // send the request to server
            out.write(req);
            out.flush();

            ByteArrayOutputStream bufferedStream = new ByteArrayOutputStream();
            IOUtils.copy(in, bufferedStream);
            
            InputStream lookAheadIN = new ByteArrayInputStream(bufferedStream.toByteArray());
            String lookAheadVersion = readLine(lookAheadIN);
            String lookAheadResponse = readLine(lookAheadIN);
            
            if (lookAheadVersion.endsWith(MyProxyConstants.VERSION) && 
                lookAheadResponse.equals(RESPONSE + "1")) {
            	
            	logger.debug("Received an error message instead of certificates!");
            	
            	String error = null;
            	StringBuffer errorMessage = new StringBuffer();
            	while ((error = readLine(lookAheadIN)) != null) {
            		errorMessage.append(error);
            	}
            	
            	throw new MyProxyVomsException(errorMessage.toString());
            }
            
            InputStream bufferedIN = new ByteArrayInputStream(bufferedStream.toByteArray());
            
            // read the number of certificates
            int size = bufferedIN.read();
            
            if (logger.isDebugEnabled()) {
                logger.debug("Reading " + size + " certs");
            }

            //System.out.println("---------------- GET ERROR ---------------------");
            
            //String readLine;
            //BufferedReader br = new BufferedReader(new InputStreamReader(in));
            //while (((readLine = br.readLine()) != null)) {
            //	System.out.println(readLine);
            //}
            //System.out.println("---------------- GET ERROR ---------------------");
            
            
            
            X509Certificate [] chain
                = new X509Certificate[size];

            for (int i=0;i<size;i++) {
                chain[i] = certFactory.loadCertificate(bufferedIN);
                // DEBUG: display the cert names
                if (logger.isDebugEnabled()) {
                    logger.debug("Received cert: " + chain[i].getSubjectDN());
                }
            }

            // get the response
            handleReply(bufferedIN);

            // make sure the protected key belongs to the right public key
            // currently only works with RSA keys
            RSAPublicKey pkey   = (RSAPublicKey)chain[0].getPublicKey();
            RSAPrivateKey prkey = (RSAPrivateKey)keyPair.getPrivate();

            if (!pkey.getModulus().equals(prkey.getModulus())) {
                throw new MyProxyException("Private/Public key mismatch!");
            }

            X509Credential newCredential = null;

            newCredential = new X509Credential(keyPair.getPrivate(),
                                                 chain);

            return new GlobusGSSCredentialImpl(newCredential,
                                               GSSCredential.INITIATE_AND_ACCEPT);

        } catch(Exception e) {
        	if (e instanceof MyProxyVomsException) {
        		throw (MyProxyVomsException)e;
        	} else {
        		throw new MyProxyException("MyProxy get failed.", e);
        	}
        } finally {
            // close socket
            close(out, in, gsiSocket);
        }    	
    
    }
    
    
    
}
