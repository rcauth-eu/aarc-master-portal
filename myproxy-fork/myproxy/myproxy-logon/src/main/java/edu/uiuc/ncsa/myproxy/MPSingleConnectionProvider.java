package edu.uiuc.ncsa.myproxy;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.ConnectionException;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;

import javax.net.ssl.KeyManagerFactory;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

/**
 * Creates a single {@link MyProxyConnectable} object for a given configuration.
 * Generally this is used internally by the {@link MPConnectionProvider} class.
 * <p>Created by Jeff Gaynor<br>
 * on 1/23/14 at  9:38 AM
 */
public class MPSingleConnectionProvider<T extends MyProxyConnectable> implements javax.inject.Provider<T> {
    String username;
    String hostname;
    String password;
    int port;
    long socketTimeout = 0L;
    long lifetime;// note this must be converted to seconds for MyProxy!
    KeyManagerFactory keyManagerFactory;
    MyLoggingFacade facade;
    String serverDN;

    public MPSingleConnectionProvider(MyLoggingFacade logger,
                                      String username,
                                      String password,
                                      long lifetime,
                                      MyProxyServiceFacade facade
    ) throws IOException, GeneralSecurityException {
        this(logger, username, password, null, lifetime, facade);
    }

    public MPSingleConnectionProvider(MyLoggingFacade logger,
                                      String username,
                                      String password,
                                      String loa,
                                      long lifetime,
                                      MyProxyServiceFacade facade
    ) throws IOException, GeneralSecurityException {
        this(logger,
                username,
                password,
                facade.getFacadeConfiguration().getHostname(),
                facade.getLOAPort(loa),
                lifetime,
                facade.getFacadeConfiguration().getSocketTimeout(),
                facade.getKeyManagerFactory(),
                facade.getFacadeConfiguration().getServerDN());
    }


    public MPSingleConnectionProvider(MyLoggingFacade logger,
                                      String username,
                                      String password,
                                      String hostname,
                                      int port,
                                      long lifetime,
                                      long socketTimeout,
                                      KeyManagerFactory keyManagerFactory,
                                      String serverDN) {
        this.username = username;
        if (password == null) {
            this.password = "";
        } else {
            this.password = password;
        }
        this.port = port;
        this.lifetime = lifetime;
        this.hostname = hostname;
        this.keyManagerFactory = keyManagerFactory;
        this.facade = logger;
        this.socketTimeout = socketTimeout;
        this.serverDN = serverDN;
    }

    public static class MyProxyLogonConnection implements MyProxyConnectable {
        public MyProxyLogonConnection(MyProxyLogon myProxyLogon) {
            this.myProxyLogon = myProxyLogon;
        }
        
		@Override
		public void doPut(X509Certificate[] chain, PrivateKey privateKey) throws Throwable {
			throw new NotImplementedException();
		}

		@Override
		public void doStore(X509Certificate[] chain, PrivateKey privateKey) throws Throwable {
			throw new NotImplementedException();
		}
		
        @Override
        public String doInfo() {
        	throw new NotImplementedException();
        }
        
        @Override
        public void setVoname(String voname) {
        	if (myProxyLogon != null && voname != null) {
                if ( myProxyLogon.getVoname() == null || ! myProxyLogon.getVoname().equals(voname) ) {
                    // don't reset the connection, instead just close it. 
                	// myProxyLogon.logon() will open in on demand anyway
                	myProxyLogon.setVoname(voname);
                    if (myProxyLogon.isLoggedOn()) {
                        close();
                    }
                }
            }
        }
        
        @Override
        public void setVomses(String vomses) {
            if (myProxyLogon != null && vomses != null) {
                if ( myProxyLogon.getVomses() == null || ! myProxyLogon.getVomses().equals(vomses) ) {
                    // don't reset the connection, instead just close it. 
                	// myProxyLogon.logon() will open in on demand anyway
                    myProxyLogon.setVomses(vomses);
                    if (myProxyLogon.isLoggedOn()) {
                        close();
                    }
                }
            }
        }
        
        @Override
        public void setLifetime(long certLifetime) {
            if (myProxyLogon != null) {
                int newLifetime = (int) (certLifetime / 1000);
                if (myProxyLogon.getLifetime() != newLifetime) {
                    // only go to the trouble of resetting this and re-acquiring the connection if there is a change.
                    myProxyLogon.setLifetime(newLifetime);
                    if (myProxyLogon.isLoggedOn()) {
                        close();
                    }
                }
            }
        }

        MyProxyLogon myProxyLogon;


        @Override
        public void close() {
            try {
                myProxyLogon.disconnect();
            } catch (Throwable e) {
                throw new ConnectionException("Error: disconnecting from myproxy", e);
            }

        }

        @Override
        public void open() {
            try {
                myProxyLogon.connect();
                myProxyLogon.logon();
            } catch (Throwable e) {
                throw new ConnectionException("Error: connecting to myproxy", e);
            }
        }

        @Override
        public String toString() {
            String out =  getClass().getSimpleName() + "[";
            if(myProxyLogon == null){
                out = out + "(no myproxy logon)";
            }else {
                out = out + "lifetime=" + myProxyLogon.getLifetime() +
                        ", port=" + myProxyLogon.getPort() +
                        ", host="+ myProxyLogon.getHost();
            }
              return out + "]";
        }

        @Override
        public LinkedList<X509Certificate> getCerts(MyPKCS10CertRequest pkcs10CertRequest) {
            try {
                myProxyLogon.getCredentials(pkcs10CertRequest.getEncoded());
                LinkedList<X509Certificate> certList = new LinkedList<X509Certificate>();
                certList.addAll(myProxyLogon.getCertificates());
                return certList;
            } catch (Throwable e) {
                System.err.println(getClass().getSimpleName() + ".getCerts: failed!");
                e.printStackTrace();
                throw new GeneralException("Error: getting certs from myproxy", e);
            }
        }

        Identifier identifier;

        @Override
        public Identifier getIdentifier() {
            return identifier;
        }

        @Override
        public String getIdentifierString() {
            if (identifier == null) return null;
            return identifier.toString();
        }

        @Override
        public void setIdentifier(Identifier identifier) {
            this.identifier = identifier;
        }




    } //end inner class

    @Override
    public T get() {
        MyProxy myproxy = null;
        if (facade == null) {
        	myproxy = new MyProxy();
        } else {
        	myproxy = new MyProxy(facade, serverDN);
        }
        myproxy.setHost(hostname);
        // Fix for CIL-153, CIL-147
        myproxy.setLifetime((int) (lifetime / 1000));
        myproxy.setPort(port);
        myproxy.setSocketTimeout(socketTimeout);
        myproxy.setUsername(username);
        myproxy.setPassphrase(password);
        myproxy.setKeyManagerFactory(keyManagerFactory);
        return (T) new MyProxyConnection(myproxy);
    }
}
