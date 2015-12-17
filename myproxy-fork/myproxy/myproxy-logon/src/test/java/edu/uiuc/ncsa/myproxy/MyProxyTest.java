package edu.uiuc.ncsa.myproxy;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;

import org.junit.Test;

import edu.uiuc.ncsa.myproxy.MyProxyLogonTest.TestProperties;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;

public class MyProxyTest extends MyProxyLogonTest {

	public final static String MYPROXY_TEST_CERTDIR_KEY = "myproxy.test.certdir";
	public final static String MYPROXY_TEST_SERVER_DN_KEY = "myproxy.test.serverdn";
	
	@Test
    public void testInfo() throws Exception {
    	
        TestProperties p = getTestProperties();
        if (p == null) {
            say("  aborting test...");
            return;
        }
        
        MyProxy mp = new MyProxy();
        
        String portString = p.getString(MYPROXY_TEST_PORT_KEY);
        if (portString == null) {
            portString = "7512"; //default
        }

        mp.setPort(Integer.parseInt(portString));
        mp.setHost(p.getString(MYPROXY_TEST_HOST_KEY));
        mp.setServerDN( p.getProperty(MYPROXY_TEST_SERVER_DN_KEY) );
        
        String lifetimeString = p.getString(MYPROXY_TEST_LIFETIME_KEY);
        if (lifetimeString == null) {
            lifetimeString = "12";
        }

        mp.setLifetime(Integer.parseInt(lifetimeString) * 3600);
        mp.setUsername(p.getString(MYPROXY_TEST_USERNAME_KEY));

        String pwd = p.getString(MYPROXY_TEST_PASSPHRASE_KEY);
        if (pwd == null || pwd.length() == 0) {
            return; // do not do the rest of the test.
        }
        mp.setPassphrase(pwd);
        char[] passphrase = pwd.toCharArray();

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(p.getString(MYPROXY_TEST_KEY_MANAGER_KEY));
        KeyStore ks = KeyStore.getInstance(p.getString(MYPROXY_TEST_KEYSTORE_KEY));

        String hostcred = p.getString(MYPROXY_TEST_HOSTCRED_KEY);
        if (hostcred == null || hostcred.length() == 0) {
            System.out.println("Warning! No host credential was found in the test.properties file.\n\nExiting...\n\n");
            return; // jump out if these properties are not set.
        }
        FileInputStream fis = new FileInputStream(hostcred);
        ks.load(fis, passphrase);
        fis.close();
        kmf.init(ks, passphrase);
        mp.setKeyManagerFactory(kmf);
        
        System.setProperty("X509_CERT_DIR", p.getString(MYPROXY_TEST_CERTDIR_KEY));

        //mp.connect();
        
        String info = mp.doInfo()[0].toString();
        say(info);        
        
        mp.disconnect();

        mp.getCredentials();

    }	

    @Test
    public void testPut() throws Exception {
    	
        TestProperties p = getTestProperties();
        if (p == null) {
            say("  aborting test...");
            return;
        }
        
        MyProxy mp = new MyProxy();
        
        String portString = p.getString(MYPROXY_TEST_PORT_KEY);
        if (portString == null) {
            portString = "7512"; //default
        }

        mp.setPort(Integer.parseInt(portString));
        mp.setHost(p.getString(MYPROXY_TEST_HOST_KEY));
        mp.setServerDN( p.getProperty(MYPROXY_TEST_SERVER_DN_KEY) );
        
        String lifetimeString = p.getString(MYPROXY_TEST_LIFETIME_KEY);
        if (lifetimeString == null) {
            lifetimeString = "12";
        }

        mp.setLifetime(Integer.parseInt(lifetimeString) * 3600);
        mp.setUsername(p.getString(MYPROXY_TEST_USERNAME_KEY));

        String pwd = p.getString(MYPROXY_TEST_PASSPHRASE_KEY);
        if (pwd == null || pwd.length() == 0) {
            return; // do not do the rest of the test.
        }
        mp.setPassphrase(pwd);
        char[] passphrase = pwd.toCharArray();

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(p.getString(MYPROXY_TEST_KEY_MANAGER_KEY));
        KeyStore ks = KeyStore.getInstance(p.getString(MYPROXY_TEST_KEYSTORE_KEY));

        String hostcred = p.getString(MYPROXY_TEST_HOSTCRED_KEY);
        if (hostcred == null || hostcred.length() == 0) {
            System.out.println("Warning! No host credential was found in the test.properties file.\n\nExiting...\n\n");
            return; // jump out if these properties are not set.
        }
        FileInputStream fis = new FileInputStream(hostcred);
        ks.load(fis, passphrase);
        fis.close();
        kmf.init(ks, passphrase);
        mp.setKeyManagerFactory(kmf);
        
        System.setProperty("X509_CERT_DIR", p.getString(MYPROXY_TEST_CERTDIR_KEY));

        mp.connect();
        
        Certificate[] chain = ks.getCertificateChain("portal");
        Key key = ks.getKey("portal", passphrase);
        
        X509Certificate[] inChain = new X509Certificate[chain.length];
        PrivateKey inKey = (PrivateKey) key;
        
        for (int i=0 ; i<chain.length ; i++) {
        	inChain[i] = (X509Certificate) chain[i];
        }
        
        try {
			mp.doPut(inChain, inKey);
		} catch (Throwable e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        mp.disconnect();

    }	    
    
}
