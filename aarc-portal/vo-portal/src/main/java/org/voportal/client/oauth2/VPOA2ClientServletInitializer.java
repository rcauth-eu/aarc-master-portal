package org.voportal.client.oauth2;

import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientServletInitializer;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;

public class VPOA2ClientServletInitializer extends OA2ClientServletInitializer {

	@Override
	public ExceptionHandler getExceptionHandler() {
        if(exceptionHandler == null){
            exceptionHandler = new VPOA2ClientExceptionHandler((ClientServlet) getServlet(), getEnvironment().getMyLogger());
        }
        return exceptionHandler;
	}
	
}
