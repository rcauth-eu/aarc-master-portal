package edu.uiuc.ncsa.security.oauth_2_0.server;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.issuers.AbstractIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.server.request.PARequest;
import edu.uiuc.ncsa.security.delegation.server.request.PAResponse;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;

import java.net.URI;

/**
 * Protected asset (cert) issuer for Oauth 2 class
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  5:05 PM
 */
public class PPI2 extends PAI2 {

    public PPI2(TokenForge tokenForge, URI address) {
        super(tokenForge, address);
        System.out.println("CONSTRUCTING PPI2!!");
    }

    @Override
    public PAResponse processProtectedAsset(PARequest paRequest) {
        try {
         //   Map<String, String> reqParamMap = OA2Utilities.getParameters(paRequest.getServletRequest());

        	System.out.println("PPI2 : processProtectedAsset !!");
        	
        	
            PPIResponse2 paResponse = new PPIResponse2();
            paResponse.setAccessToken(paRequest.getAccessToken()); // return the right access token with this, so the caller can track it
            
            System.out.println("PPI2 : returnning " + paResponse.getClass().getName());
            
            return paResponse;
        } catch (Exception x) {
            if(x instanceof RuntimeException){
                throw (RuntimeException)x;
            }
            throw new GeneralException("Error: could not get protected asset", x);
        }
    }
}
