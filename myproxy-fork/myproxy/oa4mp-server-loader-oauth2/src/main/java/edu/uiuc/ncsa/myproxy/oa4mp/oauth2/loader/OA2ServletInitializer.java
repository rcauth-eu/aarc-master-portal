package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ExceptionHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenRetentionPolicy;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.OA4MPServletInitializer;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;

import javax.servlet.ServletException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/15/14 at  12:06 PM
 */
public class OA2ServletInitializer extends OA4MPServletInitializer {
    @Override
    public ExceptionHandler getExceptionHandler() {
        if(exceptionHandler == null){
            exceptionHandler = new OA2ExceptionHandler();
        }
        return exceptionHandler;
    }

    @Override
    public void init() throws ServletException {
        if (isInitRun) return;
        super.init();
        OA2SE oa2SE = (OA2SE) getEnvironment();
        MyProxyDelegationServlet.transactionCleanup.getRetentionPolicies().clear(); // We need a different set of policies than the original one.
        MyProxyDelegationServlet.transactionCleanup.addRetentionPolicy(new RefreshTokenRetentionPolicy((RefreshTokenStore) oa2SE.getTransactionStore()));
        oa2SE.getMyLogger().info("Intialized refresh token cleanup thread");
    }

}
