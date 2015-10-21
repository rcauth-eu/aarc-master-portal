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
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VOChoosingServlet extends HttpServlet {
	
	Logger logger = Logger.getLogger(VOChoosingServlet.class.getName());

	public static final String VO_CHOOSER_PAGE="/pages/chooser.jsp";
	
	public static final String VOMSDIR_LOCATION_KEY="org.voportal.vomsdir";
	public static final String MASTER_PORTAL_KEY="org.voportal.master-portal";
	
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
		
		logger.log(Level.INFO,  vomses.length + " vomses discovered");
	}
	
	/*
	 * Fill in VOs for the JSP page and display it
	 */ 
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		String masterPortalHost = this.getServletContext().getInitParameter(MASTER_PORTAL_KEY);
		
		request.setAttribute("masterportal", masterPortalHost);
		request.setAttribute("vomses", vomses);
		
        RequestDispatcher dispatcher = request.getRequestDispatcher(VO_CHOOSER_PAGE);
        dispatcher.forward(request, response);		
	}
	
}
