package edu.uiuc.ncsa.myproxy;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import edu.uiuc.ncsa.myproxy.exception.MyProxyCertExpiredExcpetion;
import edu.uiuc.ncsa.myproxy.exception.MyProxyException;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.ConnectionException;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;

public class MyProxyConnection implements MyProxyConnectable {

	protected MyProxy myproxy;
	
	public MyProxyConnection(MyProxy myproxy) {
		this.myproxy = myproxy;
	}
	
	@Override
	public void doPut(X509Certificate[] chain, PrivateKey privateKey) throws Throwable {	
		resetConnection();
		this.myproxy.doPut(chain, privateKey);
	}
	
	
	
	@Override
	public String doInfo() throws MyProxyException {
		
		MyProxyCredentialInfo[] info = null;
		
		resetConnection();
		
		try {
					
			info = myproxy.doInfo();			

		} catch (MyProxyException e) {
			throw e;
		} catch (Throwable e) {
            throw new GeneralException("Error: getting info from myproxy", e);
        }
		
        if ( info.length > 1 ) {
        	throw new MyProxyException("Undefined behaviour! More then one certificate registered under single username");
        }
        
        long now = System.currentTimeMillis();
        if (info[0].getEndTime() < now) {	        	
        	throw new MyProxyCertExpiredExcpetion("User certificate expired in Credential Store!");
        }			
		
        return info[0].toString();
    
	}	
	
    protected Identifier identifier;

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
    
    

    @Override
    public void close() {
        try {
        	myproxy.disconnect();
        } catch (Throwable e) {
            throw new ConnectionException("Error: disconnecting from myproxy", e);
        }

    }

    @Override
    public void open() {
        try {
        	myproxy.connect();
        	//do not send any commands just yet because this connection can be 
        	//used for other commands, not just logon
        	//myproxy.logon();
        } catch (Throwable e) {
            throw new ConnectionException("Error: connecting to myproxy", e);
        }
    }

    @Override
    public LinkedList<X509Certificate> getCerts(MyPKCS10CertRequest pkcs10CertRequest) {
        try {
        	
        	resetConnection();
        	
        	myproxy.getCredentials(pkcs10CertRequest.getEncoded());
            LinkedList<X509Certificate> certList = new LinkedList<X509Certificate>();
            certList.addAll(myproxy.getCertificates());
            return certList;
        } catch (Throwable e) {
            System.err.println(getClass().getSimpleName() + ".getCerts: failed!");
            e.printStackTrace();
            throw new GeneralException("Error: getting certs from myproxy", e);
        }
    }
    
    protected void resetConnection() {
    	
    	try {
        	if ( myproxy.isLoggedOn() ) {
        		close();
        	}
    	} catch(Throwable t) {
    		myproxy.mlf.error("Failed to reset MyProxy connection!");
    	}
    	
    }
    
    @Override
    public void setVoname(String voname) {
    	
    	myproxy.setVoname(voname);
    	
    	/*
    	if (myproxy != null && voname != null) {
            if ( myproxy.getVoname() == null || ! myproxy.getVoname().equals(voname) ) {
                // don't reset the connection, instead just close it. 
            	// myProxyLogon.logon() will open in on demand anyway
            	myproxy.setVoname(voname);
                if (myproxy.isLoggedOn()) {
                    close();
                }
            }
        }
        */
    }
    
    @Override
    public void setVomses(String vomses) {
    	
    	myproxy.setVomses(vomses);
    	/*
        if (myproxy != null && vomses != null) {
            if ( myproxy.getVomses() == null || ! myproxy.getVomses().equals(vomses) ) {
                // don't reset the connection, instead just close it. 
            	// myProxyLogon.logon() will open in on demand anyway
            	myproxy.setVomses(vomses);
                if (myproxy.isLoggedOn()) {
                    close();
                }
            }
        }
        */
    }
    
    @Override
    public void setLifetime(long certLifetime) {
    	
    	int newLifetime = (int) (certLifetime / 1000);
    	myproxy.setLifetime(newLifetime);
    	
    	/*
        if (myproxy != null) {
            int newLifetime = (int) (certLifetime / 1000);
            if (myproxy.getLifetime() != newLifetime) {
                // only go to the trouble of resetting this and re-acquiring the connection if there is a change.
            	myproxy.setLifetime(newLifetime);
                if (myproxy.isLoggedOn()) {
                    close();
                }
            }
        }
        */
    }

    @Override
    public String toString() {
        String out =  getClass().getSimpleName() + "[";
        if(myproxy == null){
            out = out + "(no myproxy logon)";
        }else {
            out = out + "lifetime=" + myproxy.getLifetime() +
                    ", port=" + myproxy.getPort() +
                    ", host="+ myproxy.getHost();
        }
          return out + "]";
    }




	
}
