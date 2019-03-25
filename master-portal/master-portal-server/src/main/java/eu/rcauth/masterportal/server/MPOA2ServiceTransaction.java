package eu.rcauth.masterportal.server;

import net.sf.json.JSONObject;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;

public class MPOA2ServiceTransaction extends OA2ServiceTransaction {

    public MPOA2ServiceTransaction(AuthorizationGrant ag) {
        super(ag);
    }

    public MPOA2ServiceTransaction(Identifier identifier) {
        super(identifier);
    }

    String MPClientSessionIdentifier;

    public String getMPClientSessionIdentifier() {
        return MPClientSessionIdentifier;
    }

    public void setMPClientSessionIdentifier(String clientSessionIdentifier) {
        this.MPClientSessionIdentifier = clientSessionIdentifier;
    }

    /* Support for saving claims into the service transaction */
/*
    protected JSONObject claims;

    public JSONObject getClaims() {
        return claims;
    }

    public void setClaims(JSONObject claims) {
        this.claims = claims;
    }
*/

}
