package edu.uiuc.ncsa.security.util.ssl;

/**
 * A bean that holds the configuration for an keystore.  If you have a custom keystore, this will point to it.
 * This is needed, e.g., by MyTrustManager
 * <p>Created by Jeff Gaynor<br>
 * on Jun 27, 2010 at  11:29:15 AM
 */
public class SSLKeystoreConfiguration {
    /**
     * This path is actually part of the java specification.
     */
    public final static String JAVA_DEFAULT_KEYSTORE_PATH = System.getProperty("java.home") + "/lib/security/cacerts";
    /**
     * The default as shipped with Java. If you change the keystore, you should change the password and set it in the configuration.
     */
    public final static String JAVA_DEFAULT_KEYSTORE_PASSWORD = "changeit";
    /**
     * The default type for the built in java keystore.
     * {@value}
     */
    public final static String JAVA_DEFAULT_KEYSTORE_TYPE = "jks";

    public boolean isUseDefaultJavaKeyStore() {
        return useDefaultJavaKeyStore;
    }

    public void setUseDefaultJavaKeyStore(boolean useDefaultJavaKeyStore) {
        this.useDefaultJavaKeyStore = useDefaultJavaKeyStore;
    }

    boolean useDefaultJavaKeyStore = true;

    String keystore;
    String keystoreType = "jks";
    String keystorePassword;
    String keyManagerFactory = "SunX509";



    public void setKeyManagerFactory(String keyManagerFactory) {
        this.keyManagerFactory = keyManagerFactory;
    }

    public void setKeystorePassword(String keystorePassword) {
        this.keystorePassword = keystorePassword;
    }

    public void setKeystoreType(String keystoreType) {
        this.keystoreType = keystoreType;
    }


    public String getKeystorePassword() {
        if (keystorePassword == null && isUseDefaultJavaKeyStore()) {
            keystorePassword = JAVA_DEFAULT_KEYSTORE_PASSWORD;
        }
        return keystorePassword;
    }

    public String getKeystoreType() {
        if (keystoreType == null && isUseDefaultJavaKeyStore()) {
            keystoreType = JAVA_DEFAULT_KEYSTORE_TYPE;
        }
        return keystoreType;
    }

    char[] pwd;

    /**
     * Get the password to the keystore as a character array
     *
     * @return
     */
    public char[] getKeystorePasswordChars() {
        if (pwd == null) {
            pwd = getKeystorePassword().toCharArray();
        }
        return pwd;
    }

    public void setKeystore(String keystore) {
        this.keystore = keystore;
    }

    public String getKeystore() {
        if (keystore == null && isUseDefaultJavaKeyStore()) {
            keystore = JAVA_DEFAULT_KEYSTORE_PATH;
        }
        return keystore;
    }


    public String getKeyManagerFactory() {
        return keyManagerFactory;
    }

    public String toString() {
        return getClass().getName() + "[keystore path=" + getKeystore() + ", pwd=" + getKeystorePassword() + ", type=" + getKeystoreType() + "]";
    }
}
