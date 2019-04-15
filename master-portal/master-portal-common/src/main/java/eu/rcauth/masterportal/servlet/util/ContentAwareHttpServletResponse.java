package eu.rcauth.masterportal.servlet.util;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

public class ContentAwareHttpServletResponse extends HttpServletResponseWrapper {

    // Note that a new HttpServletResponse(Wrapper) has status 200
    protected int httpStatus=200;
    private final StringWriter sw = new StringWriter();

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

    /**
     * Note that getStatus() can be defined already in HttpServletResponseWrapper depending on Tomcat.
     * Overriding it here is safe.
     * @return httpStatus
    */
    @Override
    public int getStatus() {
        return httpStatus;
    }

    @Override
    public PrintWriter getWriter() {
        return new PrintWriter(sw);
    }

    public String getRawResponse() {
        return sw.toString();
    }
}
