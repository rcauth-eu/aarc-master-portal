package edu.uiuc.ncsa.myproxy.oa4mp.client.servlet;

import edu.uiuc.ncsa.security.servlet.ExceptionHandler;
import edu.uiuc.ncsa.security.servlet.JSPUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/9/15 at  12:01 PM
 */
public class ClientExceptionHandler implements ExceptionHandler {
    protected ClientServlet clientServlet;

    public ClientExceptionHandler(ClientServlet clientServlet) {
        this.clientServlet = clientServlet;
    }

    @Override
    public void handleException(Throwable t, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        t.printStackTrace();
        if (t.getCause() == null) {
            clientServlet.warn("2.a. Exception from the server: (no other cause)");
            request.setAttribute("cause", "(none)");
            request.setAttribute("stackTrace", "(none)");

        } else {
            clientServlet.warn("2.a. Exception from the server: " + t.getCause().getMessage());
            request.setAttribute("cause", t.getCause().getMessage());
            request.setAttribute("stackTrace", t.getCause());

        }
        clientServlet.error("Exception while trying to get cert. message:" + t.getMessage());

        if (t instanceof RuntimeException) {
            request.setAttribute("action", clientServlet.getServletContext().getContextPath());
            request.setAttribute("message", t.getMessage());
            JSPUtil.fwd(request, response, clientServlet.getCE().getErrorPagePath());
            return;
        }
        throw new ServletException("Error", t);
    }
}
