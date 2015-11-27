package edu.uiuc.ncsa.security.delegation.token;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * This wraps whatever X509 proxy is returned.
 */
public class MyX509Proxy extends MyX509Certificates {

    //protected X509Certificate[] x509Certificates;
    protected PrivateKey proxyKey;
	
    protected byte[] proxy;
    
    public MyX509Proxy(byte[] pemProxy) {
    	super(new X509Certificate[0]);
		this.proxy = pemProxy;
	}
    
    /*
    public MyX509Proxy(Collection<X509Certificate> certs, PrivateKey key) {
        this.x509Certificates = certs.toArray(new X509Certificate[certs.size()]);
        this.proxyKey = key;
    }
    
    public MyX509Proxy(X509Certificate [] x509Certificates, PrivateKey key) {
        this.x509Certificates = x509Certificates;
        this.proxyKey = key;
    }
    */
    
    public PrivateKey getProxyKey() {
		return proxyKey;
	}
    
    public byte[] getProxy() {
		return proxy;
	}

    public String getX509ProxyPEM() {
    	return new String(proxy);
    }
    
}