package edu.uiuc.ncsa.security.oauth_2_0.client;

import edu.uiuc.ncsa.security.delegation.services.AddressableServer;
import edu.uiuc.ncsa.security.delegation.services.DoubleDispatchServer;
import edu.uiuc.ncsa.security.delegation.services.Request;
import edu.uiuc.ncsa.security.delegation.services.Response;

import java.net.URI;

/**
 * Addressable Server implementation to support double dispatch pattern(?)
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  4:31 PM
 */
public class ASImpl implements AddressableServer, DoubleDispatchServer {
    public ASImpl(URI address) {
        this.address = address;
    }

    URI address;
    public URI getAddress() {
        return address;
    }

    public Response process(Request request) {
        return request.process(this);
    }
}
