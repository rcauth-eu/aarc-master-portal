package eu.rcauth.masterportal.servlet.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CookieUtils {

	/**
	 * Extract cookie from the request by its name
	 * 
	 * @param request The request object
	 * @param name The name of the cookie
	 * @return The cookie value under the provided name
	 */
    public static String getCookie(HttpServletRequest request, String name) {
    	
    	for (Cookie c : request.getCookies()) {
    		if (c.getName().equals(name)) {
    			return c.getValue();
    		}
    	}
    	return null;
    }
	
	
    /**
     * Extract cookie from the request by its name, and delete it afterwards. Deletion is done by writing 
     * the cookie back with 0 age to the response. Useful for not leaving junk behind. 
     *
     * @param request The request object
     * @param response The response object (need for deletion)
     * @param name The name of the cookie to extract
     * @return The value of the cookie under the provided name
     */
    public static String clearCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        String identifier = null;
        if (cookies != null) {
            // if there are no cookies (usually because the user surfed into a random page) then
            // exit gracefully rather than just giving some big null pointer stack trace.
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    identifier = cookie.getValue();
                    // This removes the cookie since we are done with it.
                    // This way if the user surfs to another portal there won't
                    // be a cookie clash.
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                }
            }
        }

        return identifier;
    }	
    
}