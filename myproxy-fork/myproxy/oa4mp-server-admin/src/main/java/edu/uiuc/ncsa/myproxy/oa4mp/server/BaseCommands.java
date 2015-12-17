package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.CommonCommands;
import edu.uiuc.ncsa.security.util.cli.ConfigurableCommandsImpl;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import org.apache.commons.lang.StringUtils;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/27/15 at  1:49 PM
 */
public abstract class BaseCommands extends ConfigurableCommandsImpl {

    public static final String CLIENTS = "clients";
    public static final String CLIENT_APPROVALS = "approvals";
    public static final String COPY = "copy";


    public abstract void about();

    public abstract ClientStoreCommands getNewClientStoreCommands() throws Exception;

    public abstract CopyCommands getNewCopyCommands() throws Exception;

    protected BaseCommands(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    public String getComponentName() {
        return OA4MPConfigTags.COMPONENT;
    }

    /**
     * This will take a String and append the correct number of blanks on the
     * left so it is the right width. This is used for making the banner.
     *
     * @param x
     * @param width
     * @return
     */
    protected String padLineWithBlanks(String x, int width) {
        String xx = StringUtils.rightPad(x, width, " ");
        return xx;
    }

    protected void start(String[] args) throws Exception {
        if (!getOptions(args)) {
            say("Warning: no configuration file specified. type in 'load --help' to see how to load one.");
            return;
        }
        initialize();
        about();
    }


    public ServiceEnvironment getServiceEnvironment() throws Exception {
        return (ServiceEnvironment) getEnvironment();
    }


    public ClientApprovalStoreCommands getNewClientApprovalStoreCommands() throws Exception {
        return new ClientApprovalStoreCommands(getMyLogger(), "  ", getServiceEnvironment().getClientApprovalStore());
    }

    public boolean use(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            useHelp();
            return true;
        }
        if (1 == inputLine.size()) {
            say("Sorry, you need to give the name of the component to invoke it.");
            return true;
        }
        CommonCommands storeCommands = null;
        if (inputLine.hasArg(CLIENTS)) {
            storeCommands = getNewClientStoreCommands();
        }
        if (inputLine.hasArg(CLIENT_APPROVALS)) {
            storeCommands = getNewClientApprovalStoreCommands();
        }
        if (inputLine.hasArg(COPY)) {
            storeCommands = getNewCopyCommands();
        }
        if (storeCommands != null) {
            CLIDriver cli = new CLIDriver(storeCommands);
            cli.start();
            return true;
        }

        return false;
    }


    protected boolean hasComponent(String componentName) {
        return componentName.equals(CLIENTS) || componentName.equals(CLIENT_APPROVALS) || componentName.equals(COPY);
    }

    protected void runComponent(String componentName) throws Exception {
        CommonCommands commonCommands = null;
        if (componentName.equals(CLIENTS)) {
            commonCommands = getNewClientStoreCommands();
        }
        if (componentName.equals(CLIENT_APPROVALS)) {
            commonCommands = getNewClientApprovalStoreCommands();
        }
        if (componentName.equals(COPY)) {
            commonCommands = getNewCopyCommands();
        }
        if (commonCommands != null) {
            CLIDriver cli = new CLIDriver(commonCommands);
            cli.start();

        }
    }


    protected boolean executeComponent() throws Exception {
          if (hasOption(USE_COMPONENT_OPTION, USE_COMPONENT_LONG_OPTION)) {
              String component = getCommandLine().getOptionValue(USE_COMPONENT_OPTION);
              if (component != null && 0 < component.length()) {
                  if (!hasComponent(component)) {
                      say("Unknown component name of \"" + component + "\". ");
                      return false;
                  }
                  runComponent(component);
                  return true;
              } else {
                  say("Caution, you specified using a component, but did not specify what the component is.");
              }
          }
          return false;
      }
    public void useHelp() {
        say("Choose the component you wish to use.");
        say("you specify the component as use + name. Supported components are");
        say(CLIENTS + " - edit client records");
        say(CLIENT_APPROVALS + " - edit client approval records\n");
        say(COPY + " - copy an entire store.\n");
        say("e.g.\n\nuse " + CLIENTS + "\n\nwill call up the client management component.");
        say("Type 'exit' when you wish to exit the component and return to the main menu");
    }

}
