package org.voportal.servlet;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.italiangrid.voms.VOMSAttribute;
import org.italiangrid.voms.VOMSGenericAttribute;
import org.italiangrid.voms.VOMSValidators;
import org.italiangrid.voms.ac.VOMSACValidator;
import org.italiangrid.voms.ac.VOMSValidationResult;
import org.italiangrid.voms.error.VOMSValidationErrorMessage;

public class VomsProxyInfoServlet extends HttpServlet {

	public static String REQ_USERNAME = "username";
	
	public static String PROXY_DIR = "/tmp";
	
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		String username = request.getParameter(REQ_USERNAME);
		
		System.out.println("VOPORTAL: Got username : " + username);
		
		FileInputStream fis = new FileInputStream(PROXY_DIR + "/" + username + ".proxy");
		BufferedInputStream bis = new BufferedInputStream(fis);

		X509Certificate[] chain =  new X509Certificate[1];
		
		try {
		
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
	
			//while (bis.available() > 0) {
				
			System.out.println("CERT 1");
			X509Certificate cert1=(X509Certificate) certFactory.generateCertificate(bis);
		    System.out.println(cert1.toString());
		    
		    chain[0] = cert1;

			System.out.println("CERT 2");
			X509Certificate cert2=(X509Certificate) certFactory.generateCertificate(bis);
		    System.out.println(cert2.toString());

		    chain[0] = cert2;
		    
		    //}

			
		}
		catch (Exception e) {
			System.out.println(e);
			e.printStackTrace();
		}
		 
		
		
		VOMSACValidator validator = VOMSValidators.newValidator();
		
		//X509Certificate[] ar = (X509Certificate[]) chain.toArray();
		//System.out.println("CAST LENGTH:" + ar.length);
		
		List<VOMSValidationResult> results =  validator.validateWithResult(chain);
		
		System.out.println("AN RESULT? " + results.size());
		
		for(VOMSValidationResult r: results){

			System.out.println("NEW RESULT");
			
		    if ( r.isValid() ){
		        VOMSAttribute attrs = r.getAttributes();
			    List<String> fqans = attrs.getFQANs();

				System.out.println("FQANs:" + fqans.size());
			    for (String f: fqans)
			        System.out.println(f);

			    List<VOMSGenericAttribute>  gas = attrs.getGenericAttributes();
				System.out.println("GASs:" + gas.size());
			    for (VOMSGenericAttribute g: gas)
			        System.out.println(g);
		    }else{
		        
		    	System.out.println("FAILED VALIDATION");
		    	
		    	List<VOMSValidationErrorMessage> errors =  r.getValidationErrors();
		    	for (VOMSValidationErrorMessage e : errors) {
		    		System.out.println(e.getMessage());
		    	}
		    }
		}
		
	}
	
}
