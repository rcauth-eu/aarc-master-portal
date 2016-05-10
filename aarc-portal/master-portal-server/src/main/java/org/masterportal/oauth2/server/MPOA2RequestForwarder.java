package org.masterportal.oauth2.server;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;
import org.masterportal.oauth2.servlet.util.ContentAwareHttpServletResponse;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

public class MPOA2RequestForwarder {

	/**
	 *  Forward requests to another endpoint. This method is used by the OA4MP-Server to forward 
	 *  calls to the OA4MP-Client. This method abstract error handling based on returned status
	 *  codes.
	 */
	public static void forwardRequest(HttpServletRequest request, HttpServletResponse response, 
									  RequestDispatcher dispatcher, boolean aggregateResponse)  throws Throwable {
		
		
		ContentAwareHttpServletResponse responseWrapper = new ContentAwareHttpServletResponse(response);
		
		if (aggregateResponse) {
			dispatcher.include(request , responseWrapper ); 
		} else {
			dispatcher.forward(request, responseWrapper );
		}
        
        if (responseWrapper.getStatus() == HttpStatus.SC_NO_CONTENT) {
        	throw new GeneralException("Master Portal (OA4MP Client) returned an empty response");
        }

        String x = responseWrapper.getRawResponse();
        
        // everything other than OK will trigger an exception in the OA4MP Server
        if (responseWrapper.getStatus() != HttpStatus.SC_OK) {

            throw new GeneralException(x);
        }
		
	}
	
}
