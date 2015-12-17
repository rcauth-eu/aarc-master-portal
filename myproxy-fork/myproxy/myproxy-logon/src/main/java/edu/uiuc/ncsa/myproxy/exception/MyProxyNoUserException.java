package edu.uiuc.ncsa.myproxy.exception;

public class MyProxyNoUserException extends MyProxyException {

	public MyProxyNoUserException(String msg) {
		super(msg);
		// TODO Auto-generated constructor stub
	}
	
    public MyProxyNoUserException(String msg, Throwable ex) {
        super(msg, ex);
    }	

}