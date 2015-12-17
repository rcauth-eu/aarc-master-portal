package edu.uiuc.ncsa.security.delegation.token;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;
import edu.uiuc.ncsa.security.util.pkcs.ProxyUtil;

/**
 * A proxy extension class capable of storing the private key as well next to the certificates
 * <p>Created by Tamas Balogh<br>
 */
public class MyX509Proxy extends MyX509Certificates {

    protected PrivateKey proxyKey;
	
    protected byte[] proxy;
    
    public MyX509Proxy(byte[] pemProxy) {
    	super(ProxyUtil.certificatesFromProxy(pemProxy));
		this.proxyKey = ProxyUtil.keyFromProxy(pemProxy);
    	this.proxy = pemProxy;
	}

    public MyX509Proxy(MyX509Certificates certs, PrivateKey key) {
        super(certs.getX509Certificates());
        this.proxyKey = key;
    }
    
    public MyX509Proxy(X509Certificate[] certs, PrivateKey key) {
        super(certs);
        this.proxyKey = key;
    }
    
    public PrivateKey getProxyKey() {
		return proxyKey;
	}
    
    public byte[] getProxy() throws CertificateEncodingException {
    	if (proxy == null || proxy.length == 0) {
    		proxy = this.getX509CertificatesPEM().getBytes();
    	} 
		return proxy;
	}

    public String getX509ProxyPEM() {
    	return new String(proxy);
    }
    
    @Override
    public String getX509CertificatesPEM() throws CertificateEncodingException {

    	if (proxy != null && proxy.length != 0) {
    		return new String(proxy);
    	} else {
            String pem = "";
           
            if ( x509Certificates.length > 0 ) {
            	pem += CertUtil.toPEM(x509Certificates[0]) + "\n";
            }
            
            if ( proxyKey != null ) {
            	pem += KeyUtil.toPKCS8PEM(proxyKey) + "\n";
            }
            
            for (int i = 1; i < x509Certificates.length; ++i){
                pem += CertUtil.toPEM(x509Certificates[i]) + "\n";
            }
            return pem;
    	}
    }
    
}