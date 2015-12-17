package edu.uiuc.ncsa.security.servlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/6/15 at  4:29 PM
 */
public interface ExceptionHandler {
    /**
     * This has to throw these two exceptions for servlets.
     * @param t
     * @param request
     * @param response
     * @throws IOException
     * @throws ServletException
     */
    public void handleException(Throwable t, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException;
}
