package edu.uiuc.ncsa.security.delegation.server.request;

import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.services.Response;
import edu.uiuc.ncsa.security.delegation.services.Server;
import edu.uiuc.ncsa.security.delegation.storage.Client;

import javax.servlet.http.HttpServletRequest;


public class PPRequest extends PARequest {
	
    public PPRequest(HttpServletRequest servletRequest, Client client) {
        super(servletRequest, client);
    }

    @Override
    public Response process(Server server) {
        if (server instanceof PAIssuer) {
            return ((PAIssuer) server).processProtectedAsset(this);
        }
        return super.process(server);
    }
}
