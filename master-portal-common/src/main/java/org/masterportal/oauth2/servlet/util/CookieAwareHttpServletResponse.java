package org.masterportal.oauth2.servlet.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

public class CookieAwareHttpServletResponse extends HttpServletResponseWrapper {

	protected List<Cookie> cookies = new ArrayList<Cookie>();
	
	public CookieAwareHttpServletResponse(HttpServletResponse response) {
		super(response);
	}

    @Override
    public void addCookie (Cookie aCookie) {
        cookies.add (aCookie);
        super.addCookie(aCookie);
    }

    public List<Cookie> getCookies () {
        return Collections.unmodifiableList(cookies);
    }	
	
    public String getCookie(String name) {
    	
    	for (Cookie c : cookies) {
    		if (c.getName().equals(name)) {
    			return c.getValue();
    		}
    	}
    	
    	return null;
    }
}
