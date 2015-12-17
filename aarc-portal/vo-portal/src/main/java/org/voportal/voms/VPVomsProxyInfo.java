package org.voportal.voms;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;

import org.italiangrid.voms.clients.ProxyInfoParams;
import org.italiangrid.voms.clients.ProxyInfoParams.PrintOption;
import org.italiangrid.voms.clients.VomsProxyInfo;
import org.italiangrid.voms.clients.impl.DefaultVOMSProxyInfoBehaviour;
import org.italiangrid.voms.clients.impl.ProxyInfoListenerHelper;
import org.italiangrid.voms.clients.strategies.ProxyInfoStrategy;

public class VPVomsProxyInfo extends VomsProxyInfo {

	private VPVomsProxyInfo(String[] args) {
		super(args);
	}
	
	public static String exec(String proxyFile) throws UnsupportedEncodingException {
		
		ProxyInfoParams params = new ProxyInfoParams();
		params.setProxyFile(proxyFile);
		params.addPrintOption(PrintOption.ALL_OPTIONS);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ByteArrayOutputStream err = new ByteArrayOutputStream();
		PrintStream pOut = new PrintStream(out);
		PrintStream pErr = new PrintStream(err);
		
		VPBufferedMessageLogger bufferedLogger = new VPBufferedMessageLogger(pOut, pErr);
		ProxyInfoListenerHelper listenerHelper = new ProxyInfoListenerHelper(bufferedLogger);
		
		ProxyInfoStrategy  proxyInfoBehaviour = new DefaultVOMSProxyInfoBehaviour(bufferedLogger,
	  	        listenerHelper);
	  	proxyInfoBehaviour.printProxyInfo(params);
	  	
	  	return out.toString("UTF8");
	  	
	  	/*
	  	System.out.println("-----------------VOMS_PROXY_INFO--------------------");
	  	System.out.println("OUT:");
	  	System.out.println(out.toString("UTF8"));
	  	System.out.println("OUT:");
	  	System.out.println(out.toByteArray());
	  	System.out.println("ERR:");
	  	System.out.println(err.toByteArray());
	  	System.out.println("-----------------VOMS_PROXY_INFO--------------------");		
		
	  	return null;
	  	*/
		
	}
	
}
