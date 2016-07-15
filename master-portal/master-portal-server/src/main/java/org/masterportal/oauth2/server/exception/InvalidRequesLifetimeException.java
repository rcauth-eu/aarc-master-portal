package org.masterportal.oauth2.server.exception;

import edu.uiuc.ncsa.myproxy.exception.MyProxyException;

public class InvalidRequesLifetimeException extends MyProxyException {
	
	public InvalidRequesLifetimeException(String msg) {
		super(msg);
	}	
	
    public InvalidRequesLifetimeException(String msg, Throwable ex) {
        super(msg, ex);
    }		
	
}
