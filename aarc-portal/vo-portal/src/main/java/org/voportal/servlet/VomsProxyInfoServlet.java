package org.voportal.servlet;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.voportal.voms.VPVomsProxyInfo;

public class VomsProxyInfoServlet extends HttpServlet {
	
	public static String VOMS_INFO_PAGE = "/pages/vomsinfo.jsp";

	public static String REQ_USERNAME = "username";
	
	public static String PROXY_DIR = "/tmp";
	
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		String username = request.getParameter(REQ_USERNAME);
		
		if (username == null || username.isEmpty()) {
			throw new ServletException("No username specified!");
		}
		
		String vomsinfo = null;
		
		try {
			
			vomsinfo = VPVomsProxyInfo.exec(PROXY_DIR + "/" + username + ".proxy");
			
		}
		catch (Exception e) {
			
			System.out.println(e);
			e.printStackTrace();
			
			throw new ServletException("Unable to get voms-info! \nPartial info" + vomsinfo,e);
			
		}
		
		//read proxy certificate from expected file location
		FileInputStream fis = new FileInputStream(PROXY_DIR + "/" + username + ".proxy");
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		byte[] proxy = new byte[bis.available()];
		bis.read(proxy);
		fis.close();
		
		String proxyString = new String(proxy);
		
		request.setAttribute("vomsinfo", vomsinfo);
		request.setAttribute("proxy", proxyString);
		
        RequestDispatcher dispatcher = request.getRequestDispatcher(VOMS_INFO_PAGE);
        dispatcher.forward(request, response);	
		
	}
	
}
