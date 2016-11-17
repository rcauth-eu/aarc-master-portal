package org.masterportal.oauth2.server.exception;

import edu.uiuc.ncsa.myproxy.exception.MyProxyException;

public class InvalidRequestLifetimeException extends MyProxyException {
	
	public InvalidRequestLifetimeException(String msg) {
		super(msg);
	}	
	
    public InvalidRequestLifetimeException(String msg, Throwable ex) {
        super(msg, ex);
    }		
	
}
