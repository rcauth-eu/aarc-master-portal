package org.masterportal.oauth2.server.exception;

public class InvalidDNException extends Exception {

	public InvalidDNException(String msg) {
		super(msg);
	}	
	
    public InvalidDNException(String msg, Throwable ex) {
        super(msg, ex);
    }		
	
}
