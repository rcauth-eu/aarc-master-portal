package org.masterportal.oauth2.servlet.util;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

public class ContentAwareHttpServletResponse extends HttpServletResponseWrapper {

	protected int httpStatus;
	protected StringWriter sw = new StringWriter();
	
	public ContentAwareHttpServletResponse(HttpServletResponse response) {
		super(response);
	}

    @Override
    public void sendError(int sc) throws IOException {
        httpStatus = sc;
        super.sendError(sc);
    }

    @Override
    public void sendError(int sc, String msg) throws IOException {
        httpStatus = sc;
        super.sendError(sc, msg);
    }

    @Override
    public void setStatus(int sc) {
        httpStatus = sc;
        super.setStatus(sc);
    }

    public int getStatus() {
        return httpStatus;
    }
    
    @Override
    public PrintWriter getWriter() throws IOException {
    	return new PrintWriter(sw);
    }
   
    public String getRawResponse() {
    	return sw.toString();
    }
}
