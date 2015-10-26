package org.voportal.servlet;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.servlet.RequestDispatcher;
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
	
	public static String VOMS_INFO_PAGE = "/pages/vomsinfo.jsp";

	public static String REQ_USERNAME = "username";
	
	public static String PROXY_DIR = "/tmp";
	
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		String username = request.getParameter(REQ_USERNAME);
		
		if (username == null || username.isEmpty()) {
			throw new ServletException("No username specified!");
		}
		
		FileInputStream fis = null;

		VOMSACValidator validator = null;
		
		StringBuilder vomsinfo = new StringBuilder();
		
		try {
			//read proxy certificate from expected file location
			fis = new FileInputStream(PROXY_DIR + "/" + username + ".proxy");
			BufferedInputStream bis = new BufferedInputStream(fis);
			
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			ArrayList<X509Certificate> certChain = new ArrayList<X509Certificate>();		
				
			//loading the proxy certificate
			X509Certificate proxycert =(X509Certificate) certFactory.generateCertificate(bis);
		    certChain.add(proxycert);
			
		    //skipping the private key
		    String line = readLine(bis);
		    while (! line.equals("-----END RSA PRIVATE KEY-----")) {
		    	line = readLine(bis);
		    }
		    
		    //loading the rest of the certificates 
		    while (bis.available() > 0) {
		    	X509Certificate cert=(X509Certificate) certFactory.generateCertificate(bis);
		    	certChain.add(cert);
		    }
		    
		    //start validator 
			validator = VOMSValidators.newValidator();
			
			//convert certificate chain and validate
			X509Certificate[] chain =  certChain.toArray(new X509Certificate[certChain.size()]);
			List<VOMSValidationResult> results =  validator.validateWithResult(chain);
			
			//collect printable data			
			
			vomsinfo.append("subject    : " + proxycert.getSubjectDN() + "<br />");
			vomsinfo.append("issuer     : " + proxycert.getIssuerDN() + "<br />");
			vomsinfo.append("identity   : " + chain[chain.length-1].getSubjectDN() + "<br />");
			//vomsinfo.append("type       : " +  "TODO");
	        
	        RSAPublicKey pub = (RSAPublicKey) proxycert.getPublicKey();
	        vomsinfo.append("strength   : " + pub.getModulus().bitLength() + "<br />");

		    Date notAfter = proxycert.getNotAfter();
		    long diffInMillies = (notAfter.getTime() - (new Date()).getTime());
		    long seconds=(diffInMillies/1000)%60;
		    long minutes=(diffInMillies/(1000*60))%60;
		    long hours=(diffInMillies/(1000*60*60))%24;
		    vomsinfo.append("timeleft   : " + hours + ":" + minutes + ":" + seconds + "<br />");
		    
		    vomsinfo.append("key usage  : ");
		    for (int i=0 ; i<proxycert.getKeyUsage().length ; i++) {
		    	if (proxycert.getKeyUsage()[i]) {
		    		vomsinfo.append(getKeyUsageString(i) + " ");
		    	}
		    }
		    vomsinfo.append("<br />");

			for(VOMSValidationResult r: results){
		
			    if ( r.isValid() ){
			        VOMSAttribute attrs = r.getAttributes();
			        
			        vomsinfo.append("=== VO " + attrs.getVO() + " extension information ===<br />");
			        vomsinfo.append("VO         : " + attrs.getVO() + "<br />");
			        vomsinfo.append("subject    : " + attrs.getHolder() + "<br />");
			        vomsinfo.append("issuer     : " + attrs.getIssuer() + "<br />");
			        
				    for (String f: attrs.getFQANs()) {
				    	vomsinfo.append("attribute  : " + f + "<br />");
				    }
				    
				    vomsinfo.append("timeleft   : " + hours + ":" + minutes + ":" + seconds + "<br />");
				    vomsinfo.append("uri        : " + attrs.getHost() + ":" + attrs.getPort() + "<br />");
			        
			    }else{
			        
			    	vomsinfo.append("=== FAILED VALIDATION ===" + "<br />");
			    	
			    	List<VOMSValidationErrorMessage> errors =  r.getValidationErrors();
			    	for (VOMSValidationErrorMessage e : errors) {
			    		vomsinfo.append(e.getMessage());
			    	}
			    }
			}
			
		}
		catch (Exception e) {
			System.out.println(e);
			e.printStackTrace();
			
			throw new ServletException("Unable to get voms-info! \nPartial info" + vomsinfo,e);
			
		} finally {
			if (validator != null) {
				validator.shutdown();
			}
			if (fis != null) {
				fis.close();
			}
		}
		
		//read proxy certificate from expected file location
		fis = new FileInputStream(PROXY_DIR + "/" + username + ".proxy");
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		byte[] proxy = new byte[bis.available()];
		bis.read(proxy);
		fis.close();
		
		String proxyString = new String(proxy);
		
		request.setAttribute("vomsinfo", vomsinfo);
		request.setAttribute("proxy", proxyString);
		
        RequestDispatcher dispatcher = request.getRequestDispatcher(VOMS_INFO_PAGE);
        dispatcher.forward(request, response);	
		
	}
	
	
	protected static String getKeyUsageString(int val) {
		
		// KeyUsage ::= BIT STRING {
		//     digitalSignature        (0),
		//     nonRepudiation          (1),
		//     keyEncipherment         (2),
		//     dataEncipherment        (3),
		//     keyAgreement            (4),
		//     keyCertSign             (5),
		//     cRLSign                 (6),
		//     encipherOnly            (7),
		//     decipherOnly            (8) 
		
		switch(val) {
		case 0: return "digitalSignature";
		case 1: return "nonRepudiation";
		case 2: return "keyEncipherment";
		case 3: return "dataEncipherment";				
		case 4: return "keyAgreement";
		case 5: return "keyCertSign";
		case 6: return "cRLSign";
		case 7: return "encipherOnly";
		case 9: return "decipherOnly";		
		default: return null;
		}
		
	}
	
	
	protected static String readLine(InputStream is) throws IOException {
        StringBuffer sb = new StringBuffer();
        for (int c = is.read(); c > 0 && c != '\n'; c = is.read()) {
            sb.append((char) c);
        }
        if (sb.length() > 0) {
            return new String(sb);
        }
        return null;
    }		
	
}
