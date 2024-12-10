# RELEASE NOTES

## Version 0.2.1 ... 0.2.4

Bugfix:

- the `/getproxy` endpoint would return an HTTP status code 500 with error
  `server_error` in case it could not retrieve a new EEC from the Delegation
  Server (DS). However, that can also happen when the latter's access token has
  expired or is no longer valid due to previous use for retrieving an EEC.   
  It now returns instead a 403 with error `invalid_request`. It will set the
  `error_description` to a string starting with "Master Portal could not
  retrieve new EEC from CA: " followed by a further reason. In case the failure
  is due to expiry of the DS's access token, the whole string starts with
  "Master Portal could not retrieve new EEC from CA: CA Access token expired,
  cannot retrieve new EEC".

Improvements:

- the `/getproxy` endpoint is extended to support getting the myproxy timeleft
  information by specifying a new GET or POST parameter `info`. Such a request
  returns a JSON containing the `username`, `timeleft`, `tolerance`,
  `max_proxy_lifetime` and `default_proxy_lifetime`:
    * `timeleft` - remaining time in seconds for the long-lived proxy.
    * `tolerance` - also in seconds, used (in combination with
      `max_proxy_lifetime`) to determine the longest `proxylifetime` that can be
      requested in a /getproxy call: `max_proxy_lifetime - tolerance`.
    * `max_proxy_lifetime` - typically the lifetime in seconds of the long-lived
      proxy, i.e. 950400 (which is 11 days). Used in combination with
      `tolerance` to determine the longest `proxylifetime` that can be requested
      in a /getproxy call.
    * `default_proxy_lifetime` - default lifetime in seconds of returned
      short-lived proxy, typically 43200 (i.e. 12 hours).

  **NOTE**: if a /getproxy call has a `proxylifetime` (or its default
  `default_proxy_lifetime`) which is longer than `timeleft`, a new long-lived
  proxy needs to be stored in the MasterPortal, meaning a new EEC needs to be
  obtained from the Delegation Server. This also applies to an `info` request.

- error handling is improved and the `/getproxy` now returns a JSON with an
  `error` and `error_description` to its client.

## Version 0.2.0

If you are upgrading from a previous release, you will need to make several
changes:

#### Update the server config file `/var/www/server/conf/cfg.xml`

* Add the following attributes to the relevant `<service>` element(s):
    * `disableDefaultStores="false"`
    * `OIDCEnabled="true"`

  The latter is optional, being the default setting.

* Make sure you have a `defaultKeyID` attribute specified in the `JSONWebKey`
  element, e.g.

       <JSONWebKey defaultKeyID="71463FFC64B4394DD96F29484E9BFB0A">
           <path>/var/www/server/conf/mp.jwk</path>
       </JSONWebKey>

  where the `defaultKeyID` value should match one of the `kid` values in the
  `mp.jwk` file.

* Remove the scopes handler by changing

       <scopes handler="org.masterportal.oauth2.server.MPForwardingScopeHandler">

  into

       <scopes>

  Alternatively, you can change just the name of the handler:

       <scopes handler="eu.rcauth.masterportal.server.MPForwardingClaimsSourceImpl">

  NOTE: it is now possible to define local scopes, i.e. scopes that are not
  forwarded to the delegation server, by adding an attribute `local` with
  boolean value set to `true`.

* Change the names of the validator handlers

        org.masterportal.oauth2.server.validators.DNValidator
        org.masterportal.oauth2.server.validators.LifetimeValidator

  into

        eu.rcauth.masterportal.server.validators.DNValidator
        eu.rcauth.masterportal.server.validators.LifetimeValidator

* When using the ssh key API, you can now restrict it to a specific scope,
  e.g. `eu.rcauth.sshkeys`. Add it as attribute to the `sshkeys` node:

       <sshkeys max="5" scope="eu.rcauth.sshkeys"/>

  Make sure it also appears in the list of supported scopes for this server.
  If the scope is not understood by the Delegation Server or not enabled for
  this MasterPortal, define it as a local scope, i.e. with an attribute
  `local` set to `true`:

       <scope local="true">eu.rcauth.sshkeys</scope>

* Add the following two new tables to the mysql schema:

        <permissions/>
        <adminClients/>

  These are necessary for the new client management API described below.

#### Update the client config file `/var/www/client/conf/cfg.xml`

* Add the following element to the relevant `<client>` element(s):
    * `<OIDCEnabled>true</OIDCEnabled>`

  This is currently optional, being the default setting.

* Make sure you have configured a `wellKnownURI` element for the Delegation
  Server in the relevant `<client>` element(s):
    * `<wellKnownUri>https://ds.example.org/oauth2/.well-known/openid-configuration</wellKnownUri>`

  When absent, signed tokens will not be verified.

#### Register the scopes for each client

Scope handling has changed and it is now necessary to explicitly enable the set
of supported scopes for each client separately.  
In order to do this, you can either:

* use the 0.2.4 version of the `oa2-cli` commandline tool, and update each
  client separately:

        /var/www/server/tools/oa2-cli
        > use clients
        > update 0
        > ...

  NOTE you will need to adapt the server `/var/www/server/conf/cfg.xml` first,
  following the instructions above.

* Alternatively, use the `mysql` commandline tool
  (username, password and database can be found in `cfg.xml`).

  *Make a backup of the client database first, e.g. using `mysqldump`!!*

  You can run a mysql command such as:

        update clients set scopes = '["openid","email","profile","edu.uiuc.ncsa.myproxy.getcert"]';

  or

        update clients set scopes = '["openid"]' where name = "SSH Key portal;

#### Effective request scopes

The effective list of scopes used in a request is the intersection of:

1. the scopes in the request itself,
2. the scopes configured as above for the specific client,
3. the scopes enabled for the server.  
   This typically includes the basic scopes
   (`openid`, `email`, `profile` and `edu.uiuc.ncsa.myproxy.getcert`)
   plus any other scopes such as `org.cilogon.userinfo` that are added to the
   `<scopes>` node of the `cfg.xml`.  
   Note that the basic scopes can be disabled using the `enabled="false"`
   attribute.

#### Client management API

It is now possible to manage clients (i.e. MasterPortals) also using a
JSON-based REST API (`/clients`) making use of special administrative client
credentials. Those admin clients can be registered using the administrative
client registration endpoint (`/admin-register`) and still need to be approved
using the command line tool (`use admins`). The API allows e.g. to create,
approve, list, update and remove clients.  
For examples and description, see
[oa4mp-server-admin-oauth2](https://github.com/rcauth-eu/OA4MP/tree/4.2-RCauth-1-release/oa4mp-server-admin-oauth2/src/main/scripts/client-scripts).

#### Revocation of refresh tokens

Using the new `/revoke` endpoint, clients can now revoke their own refresh
tokens. They need to authenticate using their client ID and secret, sent as a
"Basic" authorization header, while sending the refresh token via the `token`
request parameter.
See further [RFC7009 section 2.1](https://tools.ietf.org/html/rfc7009#section-2.1)
and [RFC6749 section 2.3.1](https://tools.ietf.org/html/rfc6749#section-2.3.1).

#### Other new features

Apart from the above changes, it is now possible to configure a client to *only*
receive limited proxies. This can be useful if that client just needs to access
storage and not use the proxy for job submission.
