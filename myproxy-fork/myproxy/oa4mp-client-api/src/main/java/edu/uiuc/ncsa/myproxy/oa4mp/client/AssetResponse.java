package edu.uiuc.ncsa.myproxy.oa4mp.client;

import edu.uiuc.ncsa.security.delegation.services.Response;
import edu.uiuc.ncsa.security.delegation.token.MyX509Certificates;

import java.security.cert.X509Certificate;

/**
 * Response from a server containing the certificate chain and user name.
 * <p>Created by Jeff Gaynor<br>
 * on 7/1/11 at  3:28 PM
 * 
 * Modified by Tamas Balogh 
 * 
 * Stores MyX509Certificates instead of x509Certificates[]. This makes sure
 * that we can return proxies with this class not just certificates.
 */
public class AssetResponse  implements Response{

    MyX509Certificates credential;
	String username;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public X509Certificate[] getX509Certificates() {
        return credential.getX509Certificates();
    }

    public void setX509Certificates(X509Certificate[] x509Certificates) {
    	if ( this.credential == null ) {
    		this.credential = new MyX509Certificates(x509Certificates);
    	} else {
    		this.credential.setX509Certificates(x509Certificates);
    	}
    }
    
    public void setCredential(MyX509Certificates credential) {
		this.credential = credential;
	}
    
    public MyX509Certificates getCredential() {
		return credential;
	}
}
