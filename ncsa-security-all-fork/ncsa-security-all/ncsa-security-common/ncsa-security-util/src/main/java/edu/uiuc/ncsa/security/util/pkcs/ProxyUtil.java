package edu.uiuc.ncsa.security.util.pkcs;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import eu.emi.security.authn.x509.proxy.ProxyRequestOptions;

/**
 *  Util class for transforming proxy certificates 
 *  <p>Created by Tamas Balogh<br>
 */
public class ProxyUtil {

    static Logger logger;
	
    public static Logger getLogger() {
        if (logger == null) {
            logger = Logger.getLogger(CertUtil.class.getName());
        }
        return logger;
    }
	
    public static  X509Certificate[] certificatesFromProxy(byte[] pemProxy) {
		return certificatesFromProxy(new String(pemProxy));
	}
    
	public static X509Certificate[] certificatesFromProxy(String pemProxy) {
		
		String pemString = new String(pemProxy);
		List<X509Certificate> certificates = new ArrayList<X509Certificate>();
		
		int certIndex = pemString.indexOf(CertUtil.BEGIN_CERTIFICATE);
		
		while ( certIndex >= 0 ) {
			
			pemString = pemString.substring(certIndex);
			
			ByteArrayInputStream inputStream = new ByteArrayInputStream(pemString.getBytes());
			try {
				
                X509Certificate cert = (X509Certificate) CertUtil.getCertFactory().generateCertificate(inputStream);
                certificates.add(cert);
                
            } catch (Exception e) {            	
            	getLogger().warning("Failed to extract certificate from proxy!");
            }
			
			pemString = pemString.substring(CertUtil.BEGIN_CERTIFICATE.length());
			certIndex =  pemString.indexOf(CertUtil.BEGIN_CERTIFICATE);
		}
		
		return certificates.toArray(new X509Certificate[0]);
	}
	
	public static PrivateKey keyFromProxy(byte[] pemProxy) {
		return keyFromProxy(new String(pemProxy));
	}
	
	public static PrivateKey keyFromProxy(String pemProxy) {
		
		PrivateKey pKey = null;
		
		try {
		
			int keyStart  = pemProxy.indexOf(KeyUtil.BEGIN_PRIVATE_KEY);
			int keyEnd  = pemProxy.indexOf(KeyUtil.END_PRIVATE_KEY);		
	
			String key = pemProxy.substring(keyStart, keyEnd + KeyUtil.END_PRIVATE_KEY.length());
			
			pKey = KeyUtil.fromPKCS8PEM(key);
			
		} catch (Exception e) {
			getLogger().severe("Failed to extract private key from proxy!");
		}
		
		return pKey;
	}
	
	public static X509Certificate[] generateProxy(MyPKCS10CertRequest csr, PrivateKey pKey, X509Certificate[] chain, long lifetime) throws Throwable {
		
		return generateProxy(csr.getEncoded(), pKey, chain, lifetime);
	}
	
	public static X509Certificate[] generateProxy(byte[] csr, PrivateKey pKey, X509Certificate[] chain, long lifetime) throws Throwable {
		
		//long hours = 24*365;
		long five_minutes = 60000 * 5;
		
		PKCS10CertificationRequest certReq = new PKCS10CertificationRequest(csr);
		
		ProxyRequestOptions proxyReq = new ProxyRequestOptions(chain, certReq);
		proxyReq.setProxyPathLimit( Integer.MAX_VALUE );
		
		long now = System.currentTimeMillis();
		Date notBefore = new Date(now - five_minutes);
		Date notAfter = new Date(now + lifetime);
		
		proxyReq.setValidityBounds(notBefore, notAfter);
		
		return ProxyGenerator.generate(proxyReq, pKey);
		
	}	
	
	
	
	public static void main(String[] args) throws IOException {
		
		File f = new File("/tmp/proxy");
		FileInputStream stream = new FileInputStream(f);
		
		int limit = stream.available();
		byte[] proxy = new byte[limit];
		stream.read(proxy);		
		
		//System.out.println(new String(proxy));
		
		//certificatesFromProxy(proxy);
		keyFromProxy(proxy);
		
		stream.close();
	}
	
}
