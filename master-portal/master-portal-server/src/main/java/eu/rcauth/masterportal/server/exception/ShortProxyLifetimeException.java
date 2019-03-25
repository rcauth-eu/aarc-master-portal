package eu.rcauth.masterportal.server.exception;

import edu.uiuc.ncsa.myproxy.exception.MyProxyException;

public class ShortProxyLifetimeException extends MyProxyException {
	
	public ShortProxyLifetimeException(String msg) {
		super(msg);
	}	
	
    public ShortProxyLifetimeException(String msg, Throwable ex) {
        super(msg, ex);
    }		
	
}
