package eu.rcauth.masterportal.server;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import javax.inject.Provider;

import edu.uiuc.ncsa.security.util.json.JSONStore;
import eu.rcauth.masterportal.server.storage.impl.SSHKeyStoreProvider;
import eu.rcauth.masterportal.server.validators.GetProxyRequestValidator;
import eu.rcauth.masterportal.server.storage.SSHKeyStore;
import eu.rcauth.masterportal.server.storage.SSHKey;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.MyProxyFacadeProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AuthorizationServletConfig;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.ATIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.servlet.UsernameTransformer;
import edu.uiuc.ncsa.security.util.mail.MailUtilProvider;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;

// Note: OA2SE super ServiceEnvironmentImpl.getClientApprovalStore() returns a
// non-templated ClientApprovalStore and likewise for getClientStore().
// For Java8 this produces a warning, hence suppress the unchecked warning.
@SuppressWarnings("unchecked")
public class MPOA2SE extends OA2SE {

    public MPOA2SE(MyLoggingFacade logger,
                   Provider<TransactionStore> tsp,
                   Provider<ClientStore> csp,
                   Provider<SSHKeyStore<SSHKey>> ssp,
                   int maxAllowedNewClientRequests,
                   long rtLifetime,
                   Provider<ClientApprovalStore> casp,
                   List<MyProxyFacadeProvider> mfp,
                   MailUtilProvider mup,
                   MessagesProvider messagesProvider,
                   Provider<AGIssuer> agip,
                   Provider<ATIssuer> atip,
                   Provider<PAIssuer> paip,
                   Provider<TokenForge> tfp,
                   HashMap<String,
                   String> constants,
                   AuthorizationServletConfig ac,
                   UsernameTransformer usernameTransformer,
                   boolean isPingable,
                   Provider<PermissionsStore> psp,
                   Provider<AdminClientStore> acs,
                   int clientSecretLength,
                   Collection<String> scopes,
                   Collection<String> localScopes,
                   ClaimSource claimSource,
                   LDAPConfiguration ldapConfiguration2,
                   boolean isRefreshTokenEnabled,
                   boolean twoFactorSupportEnabled,
                   long maxClientRefreshTokenLifetime,
                   JSONWebKeys jsonWebKeys,
                   String myproxyPassword,
                   long myproxyDefaultLifetime,
                   int maxSSHKeys,
                   String sshKeyScope,
                   boolean autoRegisterEndpoint,
                   GetProxyRequestValidator[] validators,
                   String issuer,
                   boolean utilServletEnabled,
                   boolean oidcEnabled,
                   Provider<JSONStore> jsonStoreProvider) {

        super(logger,
              tsp,
              csp,
              maxAllowedNewClientRequests,
              rtLifetime,
              casp,
              mfp,
              mup,
              messagesProvider,
              agip,
              atip,
              paip,
              tfp,
              constants,
              ac,
              usernameTransformer,
              isPingable,
              psp,
              acs,
              clientSecretLength,
              scopes,
              claimSource,
              ldapConfiguration2,
              isRefreshTokenEnabled,
              twoFactorSupportEnabled,
              maxClientRefreshTokenLifetime,
              jsonWebKeys,
              issuer,
              utilServletEnabled,
              oidcEnabled,
              jsonStoreProvider);

        this.myproxyPassword = myproxyPassword;
        this.myproxyDefaultLifetime = myproxyDefaultLifetime;

        this.validators = validators;

        this.ssp = (SSHKeyStoreProvider<SSHKeyStore<SSHKey>>)ssp;

        this.maxSSHKeys = maxSSHKeys;

        this.sshKeyScope = sshKeyScope;

        this.localScopes = localScopes;

        this.autoRegisterEndpoint = autoRegisterEndpoint;
    }

    protected GetProxyRequestValidator[] validators;

    public GetProxyRequestValidator[] getValidators() {
        return validators;
    }

    protected String myproxyPassword;

    public void setMyproxyPassword(String myproxyPassword) {
        this.myproxyPassword = myproxyPassword;
    }

    public String getMyproxyPassword() {
        return myproxyPassword;
    }

    protected long myproxyDefaultLifetime;

    public long getMyproxyDefaultLifetime() {
        return myproxyDefaultLifetime;
    }

    protected SSHKeyStoreProvider<SSHKeyStore<SSHKey>> ssp;

    protected SSHKeyStore<SSHKey> sshKeyStore;

    public SSHKeyStore<SSHKey> getSSHKeyStore() {
        if (sshKeyStore == null)
            sshKeyStore = ssp.get();

        return sshKeyStore;
    }

    protected int maxSSHKeys;

    public int getMaxSSHKeys()  {
        return maxSSHKeys;
    }

    protected String sshKeyScope;

    public String getSSHKeyScope()  {
        return sshKeyScope;
    }

    protected Collection<String> localScopes;

    public Collection<String> getLocalScopes() {
        return localScopes;
    }

    protected boolean autoRegisterEndpoint = false;

    public boolean getAutoRegisterEndpoint()    {
        return autoRegisterEndpoint;
    }

}
