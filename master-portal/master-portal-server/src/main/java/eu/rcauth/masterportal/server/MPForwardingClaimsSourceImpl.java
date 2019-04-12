package eu.rcauth.masterportal.server;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.BasicClaimsSourceImpl;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfiguration;


import javax.servlet.http.HttpServletRequest;

/* Next imports are to ease the javadoc */
import net.sf.json.JSONObject;
import edu.uiuc.ncsa.security.servlet.PresentableState;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2DiscoveryServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil;
import eu.rcauth.masterportal.server.servlet.MPOA2AuthorizationServer;

/**
 * Custom ClaimsSourceImpl that adds claims into UserInfo and IDToken.
 * We probably want to override {@link #getClaims()} in order to provide
 * a proper list of claims in the UserInfo. It is called in
 * {@link OA2DiscoveryServlet}#setValues(HttpServletRequest, JSONObject).
 * <br>
 * Currently, all the extra claims from the DS are already forwarded and put in
 * the transaction in
 * {@link eu.rcauth.masterportal.server.servlet.MPOA2AuthorizationServer#prepare(PresentableState)}
 * by
 * {@link OA2ServiceTransaction#setClaims(JSONObject)}.
 * <br>
 * If we would want to do additional fancy stuff with the claims (e.g. add
 * extra local ones) we would need to:
 * <ul><li>override {@link #process(JSONObject, ServiceTransaction)} and
 * {@link #process(JSONObject, HttpServletRequest, ServiceTransaction)}
 * <li>need additional configuration via a {@link ClaimSourceConfiguration},
 * for details see the constructor {@link #MPForwardingClaimsSourceImpl()}
 * <li>override {@link #isRunAtAuthorization()} to return true, in order not to
 * be skipped in {@link OA2ClaimsUtil#createBasicClaims}
 * </ul>
 * <br>
 * NOTE: this ClaimsSourceImpl is called 'on the way' back, when returning from
 * the mp-server to the (e.g. vo-portal) client. It is called by
 * {@link OA2ClaimsUtil#createBasicClaims(HttpServletRequest, OA2ServiceTransaction)},
 * called from
 * {@link MPOA2AuthorizationServer}#createRedirect(HttpServletRequest, HttpServletResponse, ServiceTransaction).
 * It is only invoked if both {@link #isEnabled()} and
 * {@link #isRunAtAuthorization()} are true
 * ({@link BasicClaimsSourceImpl#isEnabled()} returns true if it has a valid
 * {@link ClaimSourceConfiguration}, which additionally is set to enabled, see
 * also the constructor).
 * 
 * @author "Tamás Balogh"
 * @author "Mischa Sall&eacute;"
 */
public class MPForwardingClaimsSourceImpl extends BasicClaimsSourceImpl {

    /**
     * Constructor for a MPForwardingClaimsSourceImpl.
     * It needs to have a {@link ClaimSourceConfiguration} which is set to enabled.
     * See for example {@linkplain LDAPConfiguration}
     */
    public MPForwardingClaimsSourceImpl() {
        /* We currently don't need this ClaimsSourceImpl. */
        this.setConfiguration(null);
/*      ClaimSourceConfiguration claimSourceConfiguration = new ClaimSourceConfiguration();
        claimSourceConfiguration.setEnabled(true);
        this.setConfiguration(claimSourceConfiguration);*/
    }

    // TODO implement a getClaims that gets the list from the DS's .well-known
    // endpoint but that's only known to the client. Note that it's also not
    // strictly necessary, see claims_supported on
    // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    //  "Note that for privacy or other reasons, this might not be an
    //	 exhaustive list." 
//  /**
//   * getClaims produces the set of supported claims returned in the .well-known discovery
//   * @see BasicClaimsSourceImpl#getClaims()
//   * @return a HashSet containing the supported claims.
//   */
//  @Override
//  public Collection<String> getClaims() {
//      HashSet<String> claims = (HashSet<String>)super.getClaims();
//      claims.add("some_non_basic_supported_claim");
//      return claims;
//  }
}
