package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.BaseCommands;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientStoreCommands;
import edu.uiuc.ncsa.myproxy.oa4mp.server.CopyCommands;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.servlet.LoggingConfigLoader;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import org.apache.commons.lang.StringUtils;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  1:23 PM
 */
public class OA2Commands extends BaseCommands {
    public OA2Commands(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    public String getPrompt() {
        return "oa2>";
    }

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return new OA2ConfigurationLoader<>(getConfigurationNode(), getMyLogger());
    }

    OA2SE getOA2SE() throws Exception {
        return (OA2SE) getServiceEnvironment();
    }
    public static void main(String[] args) {
        try {
            OA2Commands oa2Commands = new OA2Commands(null);
            oa2Commands.start(args);
            CLIDriver cli = new CLIDriver(oa2Commands);
            cli.start();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    @Override
    public void about() {
        int width = 60;
        String stars = StringUtils.rightPad("", width + 1, "*");
        say(stars);
        say(padLineWithBlanks("* OA4MP2 OAuth 2/OIDC CLI (Command Line Interpreter)", width) + "*");
        say(padLineWithBlanks("* Version " + LoggingConfigLoader.VERSION_NUMBER, width) + "*");
        say(padLineWithBlanks("* By Jeff Gaynor  NCSA", width) + "*");
        say(padLineWithBlanks("*  (National Center for Supercomputing Applications)", width) + "*");
        say(padLineWithBlanks("*", width) + "*");
        say(padLineWithBlanks("* type 'help' for a list of commands", width) + "*");
        say(padLineWithBlanks("*      'exit' or 'quit' to end this session.", width) + "*");
        say(stars);
    }

    @Override
    public ClientStoreCommands getNewClientStoreCommands() throws Exception {
        OA2ClientCommands x =  new OA2ClientCommands(getMyLogger(), "  ", getServiceEnvironment().getClientStore(), getServiceEnvironment().getClientApprovalStore());
        x.setRefreshTokensEnabled(getOA2SE().isRefreshTokenEnabled());
        return x;
    }

    @Override
    public CopyCommands getNewCopyCommands() throws Exception {
        return new CopyCommands(getMyLogger(), new OA2CopyTool(), new OA2CopyToolVerifier(), getConfigFile());
    }
}
