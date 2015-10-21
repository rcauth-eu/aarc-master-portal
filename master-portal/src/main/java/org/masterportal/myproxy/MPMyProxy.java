package org.masterportal.myproxy;


import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.cert.X509Certificate;

import org.globus.gsi.gssapi.net.GssSocket;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxyException;
import org.ietf.jgss.GSSCredential;

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


            // this might have to be closed here?
            ASN1InputStream derin = new ASN1InputStream(in);
            ASN1Primitive reqInfo = derin.readObject();
            
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
    
}
