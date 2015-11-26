package edu.uiuc.ncsa.security.delegation.client.request;

import edu.uiuc.ncsa.security.delegation.services.Response;
import edu.uiuc.ncsa.security.delegation.services.Server;
import edu.uiuc.ncsa.security.oauth_2_0.client.PPServer2;

public class PPRequest extends PARequest {
	
	@Override
    public Response process(Server server) {
        if (server instanceof PPServer2) {
            return ((PPServer2) server).processPARequest(this);
        }
        return super.process(server);
    }
    
}
