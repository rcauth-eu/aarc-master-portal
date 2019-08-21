package eu.rcauth.masterportal.server.cli;

import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2Commands;
import edu.uiuc.ncsa.security.core.util.LoggingConfigLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import org.apache.commons.lang.StringUtils;

/**
 * Master Portal version of the oa2-cli. Note that we don't add any functionality,
 * but just want to override the about()
 * @see OA2Commands
 */
public class MPOA2Commands extends OA2Commands {

    public MPOA2Commands(MyLoggingFacade logger) {
        super(logger);
    }

    public static void main(String[] args) {
        try {
            MPOA2Commands oa2Commands = new MPOA2Commands(null);
            oa2Commands.start(args); // read the command line options and such to set the state
            CLIDriver cli = new CLIDriver(oa2Commands); // actually run the driver that parses commands and passes them along
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
        say(padLineWithBlanks("* Master Portal Server Version " + LoggingConfigLoader.VERSION_NUMBER, width) + "*");
        say(padLineWithBlanks("* Adapted by Nikhef for RCauth", width) + "*");
        say(padLineWithBlanks("* Originally by Jeff Gaynor  NCSA", width) + "*");
        say(padLineWithBlanks("*  (National Center for Supercomputing Applications)", width) + "*");
        say(padLineWithBlanks("*", width) + "*");
        say(padLineWithBlanks("* type 'help' for a list of commands", width) + "*");
        say(padLineWithBlanks("*      'exit' or 'quit' to end this session.", width) + "*");
        say(stars);
    }

}
