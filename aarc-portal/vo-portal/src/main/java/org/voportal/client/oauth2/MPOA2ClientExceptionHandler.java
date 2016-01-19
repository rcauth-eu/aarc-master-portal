package org.voportal.client.oauth2;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;

import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.oa4mp.oauth2.client.servlet.OA2ClientExceptionHandler;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

public class MPOA2ClientExceptionHandler extends OA2ClientExceptionHandler {

    MyLoggingFacade logger;

    public MPOA2ClientExceptionHandler(ClientServlet clientServlet, MyLoggingFacade myLogger) {
        super(clientServlet, myLogger);
        this.logger = myLogger;
    }
	
    @Override
    protected void parseContent(String content, HttpServletRequest request) {
        boolean hasValidContent = false;
        StringTokenizer st = new StringTokenizer(content, "\n");
        while (st.hasMoreElements()) {
            String currentLine = st.nextToken();
            StringTokenizer clST = new StringTokenizer(currentLine, "=");
            if (!clST.hasMoreTokens() || clST.countTokens() != 2) {
                continue;
            }
            try {
                request.setAttribute(clST.nextToken(), URLDecoder.decode(clST.nextToken(), "UTF-8").replaceAll("\n", ""));
            } catch (UnsupportedEncodingException xx) {
                // ok, try it without decoding it. (This case should never really happen)
                request.setAttribute(clST.nextToken(), clST.nextToken());
            }
            hasValidContent = true;
        }
        if (!hasValidContent) {
            logger.warn("Body or error was not parseable");
            throw new GeneralException();
        }
    }
    
}
