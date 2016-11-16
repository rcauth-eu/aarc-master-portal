package org.masterportal.oauth2.server;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;
import org.masterportal.oauth2.servlet.util.ContentAwareHttpServletResponse;

import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;

public class MPOA2RequestForwarder {

	/**
	 *  Forward requests to another endpoint. This method is used by the OA4MP-Server to forward 
	 *  calls to the OA4MP-Client. This method abstract error handling based on returned status
	 *  codes.
	 *  
	 *  @param request The original request object being forwarded
	 *  @param response The original response object
	 *  @param dispatcher The request dispatcher taking care of switching contexts
	 *  @param aggregateResponse Decides whether to aggregate the response coming from the forwarding 
	 *  with the original response object or not. 
	 *  
	 *  @throws Throwable for general errors
	 */
	public static void forwardRequest(HttpServletRequest request, HttpServletResponse response, 
									  RequestDispatcher dispatcher, boolean aggregateResponse)  throws Throwable {
		
		
		ContentAwareHttpServletResponse responseWrapper = new ContentAwareHttpServletResponse(response);
		
		if (aggregateResponse) {
			dispatcher.include(request , responseWrapper ); 
		} else {
			dispatcher.forward(request, responseWrapper );
		}
        
        // everything other than OK will trigger an exception in the OA4MP Server.
        if (responseWrapper.getStatus() != HttpStatus.SC_OK) {
			String mesg;
			if (responseWrapper.getStatus() == HttpStatus.SC_NO_CONTENT)
				mesg="Master Portal (OA4MP Client) returned an empty response";
			else
				mesg="Master Portal (OA4MP Client) returned an unexpected HTTP Status "+
					 responseWrapper.getStatus()+
					 ", raw response: "+
					 responseWrapper.getRawResponse();

			throw new OA2GeneralError(mesg,
									  OA2Errors.SERVER_ERROR,
									  "Internal server error",
									  HttpStatus.SC_INTERNAL_SERVER_ERROR);
        }
		
	}
	
}
