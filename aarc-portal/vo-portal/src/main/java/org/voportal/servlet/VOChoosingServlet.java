package org.voportal.servlet;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VOChoosingServlet extends HttpServlet {
	
	Logger logger = Logger.getLogger(VOChoosingServlet.class.getName());

	public static final String VO_CHOOSER_PAGE="/pages/chooser.jsp";
	public static final String VO_PORTAL_START="/startRequest";
	
	public static final String VOMSDIR_LOCATION_KEY="org.voportal.vomsdir";
	
	String[] vomses = null;
	
	/*
	 * Load available VOMSse in memory on startup
	 */
	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		
		// load vomses 
		String vomsdir = this.getServletContext().getInitParameter(VOMSDIR_LOCATION_KEY);
		logger.log(Level.INFO, "Loading supported vomses from " + vomsdir);
		
		File dir = new File(vomsdir);
		vomses = dir.list(new FilenameFilter() {
		  @Override
		  public boolean accept(File current, String name) {
		    return new File(current, name).isDirectory();
		  }
		});
		
		if (vomses != null) {
			logger.log(Level.INFO,  vomses.length + " vomses discovered");
		} else {
			logger.log(Level.SEVERE, "Failed to load VOMS information!");
		}
	}
	
	/*
	 * Fill in VOs for the JSP page and display it
	 */ 
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		request.setAttribute("redirect_host", getServletConfig().getServletContext().getContextPath() + VO_PORTAL_START);
		request.setAttribute("vomses", vomses);
		
        RequestDispatcher dispatcher = getServletConfig().getServletContext().getRequestDispatcher(VO_CHOOSER_PAGE);
        dispatcher.forward(request, response);
		
	}
	
}
