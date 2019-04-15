package eu.rcauth.masterportal.server.loader;

import javax.servlet.ServletContext;

import org.apache.commons.configuration.tree.ConfigurationNode;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2Bootstrapper;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;

public class MPOA2ServerBootstrapper extends OA2Bootstrapper {

    public static final String MP_OA2_CONFIG_FILE_KEY = "oa4mp:mp-oa2.server.config.file";
    public static final String MP_OA2_CONFIG_NAME_KEY = "oa4mp:mp-oa2.server.config.name";

    @Override
    public String getOa4mpConfigFileKey() {
        return MP_OA2_CONFIG_FILE_KEY;
    }

    @Override
    public String getOa4mpConfigNameKey() {
        return MP_OA2_CONFIG_NAME_KEY;
    }

    @Override
    public ConfigurationLoader getConfigurationLoader(ConfigurationNode node) throws MyConfigurationException {
        return new MPOA2ServerLoader(node);
    }

    @Override
    public ConfigurationLoader getConfigurationLoader(ServletContext servletContext) throws Exception {
        return super.getConfigurationLoader(servletContext);
    }

}
