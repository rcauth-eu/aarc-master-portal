package eu.rcauth.masterportal.server.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2DiscoveryServlet;
import eu.rcauth.masterportal.server.MPOA2SE;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;

public class MPOA2DiscoveryServlet extends OA2DiscoveryServlet {
    @Override
    protected JSONObject setValues(HttpServletRequest request, JSONObject jsonObject) {
        MPOA2SE se = (MPOA2SE) getServiceEnvironment();

        String requestURI = getRequestURI(request);
        if(requestURI.endsWith("/")){
            requestURI = requestURI.substring(0,requestURI.length()-1); // shave off trailing slash
        }

        JSONObject json = super.setValues(request, jsonObject);
        json.put("getproxy_endpoint", requestURI + "/getproxy");

        json.put("sshkey_endpoint", requestURI + "/sshkey");

        int maxKeys = se.getMaxSSHKeys();
        if (maxKeys>=0)
            json.put("sshkey_maximum_keys", maxKeys);
        String sshKeyScope = se.getSSHKeyScope();
        if (sshKeyScope!=null && !sshKeyScope.isEmpty())
            json.put("sshkey_scope", sshKeyScope);

        JSONArray sshKeyParams = new JSONArray();
        sshKeyParams.add(MPOA2SSHKeyServlet.ACTION_PARAMETER);
        sshKeyParams.add(MPOA2SSHKeyServlet.LABEL_PARAMETER);
        sshKeyParams.add(MPOA2SSHKeyServlet.PUBKEY_PARAMETER);
        sshKeyParams.add(MPOA2SSHKeyServlet.DESCRIPTION_PARAMETER);
        json.put("sshkey_parameters_supported", sshKeyParams);

        JSONArray sshKeyActions = new JSONArray();
        sshKeyActions.add(MPOA2SSHKeyServlet.ACTION_ADD);
        sshKeyActions.add(MPOA2SSHKeyServlet.ACTION_UPDATE);
        sshKeyActions.add(MPOA2SSHKeyServlet.ACTION_REMOVE);
        sshKeyActions.add(MPOA2SSHKeyServlet.ACTION_GET);
        sshKeyActions.add(MPOA2SSHKeyServlet.ACTION_LIST);
        json.put("sshkey_actions_supported", sshKeyActions);

        return json;
    }
}
