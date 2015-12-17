package test;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.italiangrid.voms.VOMSAttribute;
import org.italiangrid.voms.VOMSValidators;
import org.italiangrid.voms.ac.VOMSACValidator;
import org.italiangrid.voms.ac.VOMSValidationResult;
import org.italiangrid.voms.error.VOMSValidationErrorMessage;

public class ProxyVomsInfoTester {

	public static void main(String[] args) {

		String username="";
		String PROXY_DIR="/tmp";
		
		
		try {
		
			FileInputStream fis = new FileInputStream(PROXY_DIR + "/x509up_u1000");
			//FileInputStream fis = new FileInputStream(PROXY_DIR + "/proxy");
			BufferedInputStream bis = new BufferedInputStream(fis);

			
			ArrayList<X509Certificate> certChain = new ArrayList<X509Certificate>();
			
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			
			//loading the proxy certificate
			X509Certificate proxycert =(X509Certificate) certFactory.generateCertificate(bis);
		    //chain[0] = cert1;
			certChain.add(proxycert);
			
		    //skipping the private key
		    String line = readLine(bis);
		    while (! line.equals("-----END RSA PRIVATE KEY-----")) {
		    	line = readLine(bis);
		    }
		    
		    //loading the rest of the certificates 
		    while (bis.available() > 0) {
		    	X509Certificate cert=(X509Certificate) certFactory.generateCertificate(bis);
		    	//chain[1] = cert2;
		    	certChain.add(cert);
		    }
		    
		    //start validator 
			VOMSACValidator validator = VOMSValidators.newValidator();
			
			//convert certificate chain and validate
			X509Certificate[] chain =  certChain.toArray(new X509Certificate[certChain.size()]);
			List<VOMSValidationResult> results =  validator.validateWithResult(chain);
			

			//collect printable data
			System.out.println("subject    : " + proxycert.getSubjectDN());
	        System.out.println("issuer     : " + proxycert.getIssuerDN() );
	        System.out.println("identity   : " + chain[chain.length-1].getSubjectDN() );

	        //System.out.println("type       : " +  "TODO");
	        
	        RSAPublicKey pub = (RSAPublicKey) proxycert.getPublicKey();
	        System.out.println("strength   : " + pub.getModulus().bitLength() );

		    Date notAfter = proxycert.getNotAfter();
		    long diffInMillies = (notAfter.getTime() - (new Date()).getTime());
		    long seconds=(diffInMillies/1000)%60;
		    long minutes=(diffInMillies/(1000*60))%60;
		    long hours=(diffInMillies/(1000*60*60))%24;
		    System.out.println("timeleft   : " + hours + ":" + minutes + ":" + seconds);
		    
		    System.out.print("key usage  : ");
		    for (int i=0 ; i<proxycert.getKeyUsage().length ; i++) {
		    	if (proxycert.getKeyUsage()[i]) {
		    		System.out.print(getKeyUsageString(i) + " ");
		    	}
		    }
		    System.out.println();

			for(VOMSValidationResult r: results){
		
			    if ( r.isValid() ){
			        VOMSAttribute attrs = r.getAttributes();
			        
			        System.out.println("=== VO " + attrs.getVO() + " extension information ===");
			        System.out.println("VO         : " + attrs.getVO() );
			        System.out.println("subject    : " + attrs.getHolder() );
			        System.out.println("issuer     : " + attrs.getIssuer() );
			        
				    for (String f: attrs.getFQANs()) {
				    	System.out.println("attribute  : " + f );
				    }
				    
				    System.out.println("timeleft   : " + hours + ":" + minutes + ":" + seconds);
			        System.out.println("uri        : " + attrs.getHost() + ":" + attrs.getPort());
			        
			    }else{
			        
			    	System.out.println("FAILED VALIDATION");
			    	
			    	List<VOMSValidationErrorMessage> errors =  r.getValidationErrors();
			    	for (VOMSValidationErrorMessage e : errors) {
			    		System.out.println(e.getMessage());
			    	}
			    }
			}
			
			validator.shutdown();
			
		}
		catch (Exception e) {
			System.out.println(e);
			e.printStackTrace();
		}
		
		
	}
		
	
	public static String getKeyUsageString(int val) {
		
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
	
	
    public static String readLine(InputStream is) throws IOException {
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
