package eu.rcauth.masterportal.server.servlet;

import edu.uiuc.ncsa.security.servlet.AbstractServlet;
import eu.rcauth.masterportal.server.storage.SSHKey;
import eu.rcauth.masterportal.server.storage.sql.SQLSSHKeyStore;
import eu.rcauth.masterportal.server.MPOA2SE;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ExceptionHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;

import java.io.Writer;
import java.util.Collection;


/**
 * <p>Created by Mischa Sall&eacute;<br>
 * Simple servlet for returning the full list of public keys of all the users,
 * to be used (e.g.) in an sshd AuthorizedKeysCommand.
 * @see MPOA2SSHKeyServlet
 */
public class MPOA2SSHKeyListingServlet extends MyProxyDelegationServlet {
    private MPOA2SE se;
    private MyLoggingFacade logger;

    /** separator between username and public key fields */
    private static final String SEP = " ";

    @Override
    public void init() throws ServletException {
        super.init();
        se = (MPOA2SE)getServiceEnvironment();
        setEnvironment(se);

        // Create custom logger for exceptions and the like
        logger = getMyLogger();
        setExceptionHandler(new OA2ExceptionHandler(logger));
    }

    /**
     * Not implemented
     * @return null
     */
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) {
        return null;
    }

    /**
     * Main method called by TomCat upon receiving either a get or post (via {@link AbstractServlet}).
     * Writes the list of stored keys and usernames, space-separated to the response.
     */
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        SQLSSHKeyStore store = (SQLSSHKeyStore)se.getSSHKeyStore();
        if ( store == null) {
            logger.warn("doIt(): SSHKeyStore is null");
            throw new GeneralException("Cannot get SSH KeyStore");
        }

        Collection<SSHKey> keys = store.values();

        Writer writer = response.getWriter();
        for (SSHKey key : keys)    {
            writer.write(key.getUserName());
            writer.write(SEP);
            writer.write(key.getPubKey());
            writer.write("\n");
        }
        writer.flush();
        writer.close();
    }
}
