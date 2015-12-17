package edu.uiuc.ncsa.myproxy.exception;

public class MyProxyException extends Exception {

	public MyProxyException(String msg) {
		super(msg);
	}

	public MyProxyException(String msg, Throwable ex) {
		super(msg,ex);
	}
	
}
