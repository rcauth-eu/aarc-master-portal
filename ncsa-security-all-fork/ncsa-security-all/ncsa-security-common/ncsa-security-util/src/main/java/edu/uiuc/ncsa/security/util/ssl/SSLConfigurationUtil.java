package edu.uiuc.ncsa.security.util.ssl;

import org.apache.commons.configuration.tree.ConfigurationNode;

import java.util.List;

import static edu.uiuc.ncsa.security.core.configuration.Configurations.getFirstAttribute;

/**
 * A utility to create an SSLConfiguration from a configuration node. This is included here since
 * it is used in various places in the code base.
 * <p>Created by Jeff Gaynor<br>
 * on 3/21/14 at  3:53 PM
 */
public class SSLConfigurationUtil {

    public static final String SSL_KEYSTORE = "keystore";
    public static final String SSL_KEYSTORE_PATH = "path";
    public static final String SSL_KEYSTORE_PASSWORD = "password";
    public static final String SSL_KEYSTORE_TYPE = "type";
    public static final String SSL_KEYSTORE_FACTORY = "factory";
    public static final String SSL_KEYSTORE_USE_JAVA_KEYSTORE = "useJavaKeystore";

    public static SSLConfiguration getSSLConfiguration(ConfigurationNode node) {
        SSLConfiguration sslKeystoreConfiguration = new SSLConfiguration();
        List keystores = null;

        if (node != null) {
            keystores = node.getChildren(SSL_KEYSTORE);
        }

        if (keystores == null || keystores.isEmpty()) {
            sslKeystoreConfiguration.setUseDefaultJavaKeyStore(true); // default
        } else {
            ConfigurationNode cn2 = (ConfigurationNode) keystores.get(0);
            sslKeystoreConfiguration.setKeystore(getFirstAttribute(cn2, SSL_KEYSTORE_PATH));
            sslKeystoreConfiguration.setKeystorePassword(getFirstAttribute(cn2, SSL_KEYSTORE_PASSWORD));
            sslKeystoreConfiguration.setKeyManagerFactory(getFirstAttribute(cn2, SSL_KEYSTORE_FACTORY));
            sslKeystoreConfiguration.setKeystoreType(getFirstAttribute(cn2, SSL_KEYSTORE_TYPE));
            String x = getFirstAttribute(cn2, SSL_KEYSTORE_USE_JAVA_KEYSTORE);
            if (x == null) {
                sslKeystoreConfiguration.setUseDefaultJavaKeyStore(true); //default
            } else {
                sslKeystoreConfiguration.setUseDefaultJavaKeyStore(Boolean.parseBoolean(x)); //default
            }
        }
        return sslKeystoreConfiguration;
    }
}
