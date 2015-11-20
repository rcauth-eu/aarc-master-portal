package org.masterportal.myproxy.exception;

import org.globus.myproxy.MyProxyException;

public class MyProxyVomsException extends MyProxyException {

	public MyProxyVomsException(String msg) {
		super(msg);
	}
	
    public MyProxyVomsException(String msg, Throwable ex) {
        super(msg, ex);
    }		
	
}
