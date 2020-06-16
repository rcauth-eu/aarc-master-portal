package eu.rcauth.masterportal.server;

import edu.uiuc.ncsa.myproxy.MyProxyCredentialInfo;
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

    boolean IsInforequest;

    /**
     * @return boolean whether this is a myproxy info request
     */
    public boolean getIsInforequest() { return IsInforequest; }

    /**
     * Sets whether this is a myproxy info request
     * @param is_inforequest boolean
     */
    public void setIsInforequest(boolean is_inforequest) {
        this.IsInforequest = is_inforequest;
    }

    MyProxyCredentialInfo MpcInfo = null;

    /**
     * @return MyProxyCredentialInfo data for this request
     */
    public MyProxyCredentialInfo getMpcInfo() { return MpcInfo; }

    /**
     * Sets the MyProxyCredentialInfo data for this request
     * @param mpc_info MyProxyCredentialInfo as obtained from doInfo()
     */
    public void setMpcInfo(MyProxyCredentialInfo mpc_info) {
        this.MpcInfo = mpc_info;
    }

    long ProxyLifetimeTolerance = -1;

    /**
     * @return the tolerance in seconds for this request
     */
    public long getProxyLifetimeTolerance() { return ProxyLifetimeTolerance; }

    /**
     * Set the tolerance for this request
     * @param proxy_lifetime_tolerance the tolerance in seconds
     */
    public void setProxyLifetimeTolerance(long proxy_lifetime_tolerance) {
        this.ProxyLifetimeTolerance = proxy_lifetime_tolerance;
    }

}
