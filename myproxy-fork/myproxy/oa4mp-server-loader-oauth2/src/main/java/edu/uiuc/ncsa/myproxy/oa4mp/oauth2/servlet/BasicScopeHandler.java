package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandler;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;

import java.util.Collection;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/17/15 at  4:10 PM
 */
public class BasicScopeHandler implements ScopeHandler {
    Collection<String> scopes;

    @Override
    public Collection<String> getScopes() {
        return scopes;
    }

    /**
     * At the most basic level, this just returns the {@link UserInfo} object passed to it. Override as you deem fit.
     *
     * @param userInfo
     * @param transaction
     * @return
     * @throws UnsupportedScopeException
     */
    @Override
    public UserInfo process(UserInfo userInfo, ServiceTransaction transaction) throws UnsupportedScopeException {
        // Plain vanilla just gets the sub field and returns it.
        return userInfo;
    }

    @Override
    public void setScopes(Collection<String> scopes) {
        this.scopes = scopes;

    }
}
