package edu.uiuc.ncsa.security.util.ssl;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Jun 12, 2010 at  9:27:22 AM
 */
public class SSLConfiguration extends SSLKeystoreConfiguration {

    public SSLConfiguration() {
    }

    public void setTrustRootPath(String trustRootPath) {
        this.trustRootPath = trustRootPath;
    }

    public void setHostCred(String hostCred) {
        this.hostCred = hostCred;
    }


    public void setHostKey(String hostKey) {
        this.hostKey = hostKey;
    }


    String hostCred;
    String hostKey;
    String trustRootPath; // = "/etc/grid-security/certificates";


    public String getHostCred() {
        return hostCred;
    }

    public String getHostKey() {
        return hostKey;
    }

    public String getTrustrootPath() {
        return trustRootPath;
    }

    public String toString() {
        String x = super.toString();
        x = x + "[hostCred=" + getHostCred() + ", key=" + getHostKey() + ", trust root path=" + getTrustrootPath() + "]";
        return x;
    }
}
