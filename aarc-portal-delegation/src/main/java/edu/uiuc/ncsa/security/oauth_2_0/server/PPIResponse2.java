package edu.uiuc.ncsa.security.oauth_2_0.server;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.delegation.server.request.PAResponse;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.MyX509Certificates;
import edu.uiuc.ncsa.security.delegation.token.MyX509Proxy;
import edu.uiuc.ncsa.security.delegation.token.ProtectedAsset;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * Protected asset (cert) issuer response for OIDC. This has to include the servlet request since the headers have
 * to be processed for various bits of information.
 * <p>Created by Jeff Gaynor<br>
 * on 6/5/13 at  9:31 AM
 */
public class PPIResponse2 extends PAIResponse2 {

	@Override
    public void write(HttpServletResponse response) throws IOException {

        if (protectedAsset == null) {
            throw new GeneralException("Error, no protected asset =");
        }
        if (!(getProtectedAsset() instanceof MyX509Certificates)) {
            throw new NotImplementedException("Error, this implementation can only serialize MyX509Certificates and a protected asset of type \""
                    + getProtectedAsset().getClass().getName() + "\" was found instead");
        }
        try {
        	MyX509Proxy certs = (MyX509Proxy) getProtectedAsset();
            if(certs == null || certs.getProxy() == null){
                throw new GeneralException("Error: No certificate found.");
            }

            response.setContentType("text/plain");
            OutputStream out = response.getOutputStream();
            OutputStreamWriter osw = new OutputStreamWriter(out);

            System.out.println("PPIResponse2: wrinting out: " + certs.getProxy());
            
            out.write(certs.getProxy());
            out.flush();
            out.close();


        } catch (Exception x) {
            throw new GeneralException(x);
        }
    }
}
