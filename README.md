# aarc-master-portal

The AARC master-portal is an implementation of the MasterPortal component, which
is used as a caching component in front of the [RCauth.eu](https://rcauth.eu/)
online CA.
See e.g. https://wiki.nikhef.nl/grid/RCauth.eu_and_MasterPortal_architecture.  
It is based on a customised version of the
[OA4MP](https://github.com/rcauth-eu/OA4MP).

For release notes and important upgrading information,
see [RELEASE-NOTES.md](RELEASE-NOTES.md).

## Implementation

The Master Portal is both an OA4MP Client and a Server. From the perspective of
the VO Portal (Science gateway), the Master Portal is an OA4MP Server.
From the perspective of the RCauth Delegation Service the Master Portal is an
OA4MP Client. The Master Portal caches long lived user proxies into its backend
MyProxy Crendential Store, and returns short lived proxies on demand for
authenticated users via the VO Portal.  
Additionally, it provides an endpoint for uploading SSH public keys, which can
subsequently be used to obtain, e.g. on the commandline, short-lived proxy
certificates by ssh-ing to a special account on a co-located SSH host.

## Compiling

1. You first need to compile and install the two RCauth-adapted dependency
   libraries 
    1. [security-lib](https://github.com/rcauth-eu/security-lib) (RCauth version)
    2. [OA4MP](https://github.com/rcauth-eu/OA4MP) (RCauth version)
   
   Make sure to use the *same* version (branch or tag) for both the
   security-lib and OA4MP components.  
   For the **0.2** series of the aarc-master-portal, you must use the
   **4.2-RCauth** versions.
   
2. Checkout the right version of the aarc-master-portal.

        git clone https://github.com/rcauth-eu/aarc-master-portal
        cd aarc-master-portal

        git checkout v0.2.4
        cd master-portal

3. Build the master-portal's server and client war files

        mvn clean package

   After maven has finished you should find two separate `.war` files in their
   target directories, one for the MP Server and one for the MP Client:

        aarc-master-portal/master-portal/master-portal-server/target/mp-oa2-server.war
        aarc-master-portal/master-portal/master-portal-client/target/mp-oa2-client.war
    
4. Build the master-portal's server command line client

        mvn -pl master-portal-common,master-portal-server -P cli package

   After mvn has finished you should find the resulting cli `.jar` file
   in the target directory:
   
        aarc-master-portal/master-portal/master-portal-server/target/oa2-cli.jar
   
   NOTE: The cli tool is necessary for managing and approving client (Portal)
   registrations.  
   Also note that you need this version of the cli tool, as opposed to the one
   coming from the OA4MP component.  

## Other Resources

Background information:
* [RCauth.eu and MasterPortal documentation](https://wiki.nikhef.nl/grid/RCauth.eu_and_MasterPortal_documentation)
* [Master Portal internals](https://wiki.nikhef.nl/grid/Master_Portal_Internals)
* [Ansible scripts for the Master Portal](https://github.com/rcauth-eu/aarc-ansible-master-portal)

Demo clients:
* https://rcdemo.nikhef.nl/

Related Components:
* [RCauth.eu Delegation Server](https://github.com/rcauth-eu/aarc-delegation-server).
* [Demo VO portal](https://github.com/rcauth-eu/aarc-vo-portal)  
  this component can run inside the master portal's tomcat container,
  providing a demonstration client portal to the Master Portal.
* [SSH key portal](https://github.com/rcauth-eu/aarc-ssh-portal)  
  this component can run inside the master portal's tomcat container,
  leveraging the Master Portal's sshkey upload endpoint.
