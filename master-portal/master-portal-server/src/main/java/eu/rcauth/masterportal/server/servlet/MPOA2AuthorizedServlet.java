package eu.rcauth.masterportal.server.servlet;

import eu.rcauth.masterportal.server.servlet.MPOA2AuthorizedServletUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServlet;

public class MPOA2AuthorizedServlet extends OA2AuthorizedServlet {

    @Override
    public MPOA2AuthorizedServletUtil getInitUtil() {
        if(initUtil == null){
            initUtil = new MPOA2AuthorizedServletUtil(this);
        }
        return (MPOA2AuthorizedServletUtil)initUtil;
    }
}
