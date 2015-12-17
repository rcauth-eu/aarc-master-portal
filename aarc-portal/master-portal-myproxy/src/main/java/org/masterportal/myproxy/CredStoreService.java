package org.masterportal.myproxy;

import java.security.cert.X509Certificate;

public interface CredStoreService {

	public static final String MYPROXY_CONFIG_LOG4J = "org.globus.log4j.properties";
	public static final String MYPROXY_CONFIG_NAME_KEY = "org.globus.config.file";
	
	public void doInfo(String username) throws Exception;
	
	public byte[] doGet(String username, int lifetime, String voms_fqan) throws Exception;
	public byte[] doGet(String username, String voms_fqan) throws Exception;

	public byte[] doPutStart(String identifier,String username) throws Exception;
	public void doPutFinish(String identifier,X509Certificate[] certificates) throws Exception;
	
}
