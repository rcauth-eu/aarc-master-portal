package eu.rcauth.masterportal.servlet.util;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;


/**
 * Class to allow overriding parameters in a {@link HttpServletRequest} by extending a {@link HttpServletRequestWrapper}.
 * Currently it only overrides
 * {@link HttpServletRequestWrapper#getParameterMap()} and {@link HttpServletRequestWrapper#getParameter(String)},
 * this is probably is sufficient.
 *
 * @author Mischa Sall&eacute;
 */
public class UpdateParameterHttpServletRequest extends HttpServletRequestWrapper {
    // Note parameter are multi-valued in ServletRequestWrapper, we will only use the first
    private HashMap<String,String[]> params = null;

    public UpdateParameterHttpServletRequest(HttpServletRequest request) {
       super(request);
       params=new HashMap<String,String[]>(super.getParameterMap());
   }

    /**
     * @return new parameter {@link Map}
     */
    @Override
    public Map getParameterMap() {
        return params;
    }

    /**
     * @param key name of request parameter
     * @return new or unchanged value for parameter key
     */
    @Override
    public String getParameter(String key) {
        // value for a param a String[], return the first value
        return params.get(key)[0];
    }

    /**
     * Adds or replaces key/value pair into the request parameters.
     *
     * @param key name of request parameter
     * @param value value of request parameter
     */
    public void setParam(String key, String value ) {
        // value in params is a String[]
        params.put( key, new String[]{value});
   }
}