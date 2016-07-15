# aarc-master-portal

This is a custom [OA4MP](http://grid.ncsa.illinois.edu/myproxy/oauth/client/manuals/getting-started.xhtml)
implemetation for AARC [Pre-Piloting Work](https://wiki.nikhef.nl/grid/CILogon_Pre-Pilot_Work#Master_Portal).

**NOTE** *This is software is still in its piloting phase, and it's in no way meant to be used as a production
ready component!*

## Master Portal

The Master Portal is both a OA4MP Client and a Server. For the purpse of the VO Portal, the Master Portal is
an OA4MP Server. For the purpose of the Delegation Service the Master Portal is an OA4MP Client. The Master
Portal caches long lived user proxies into its MyProxy Crendential Store, and returns short lived proxies 
on demand for authenricated users via the VO Portal. 

## Building

In case you wish the build the Master Portal you should first build two of its dependencies in the
following order 

1. [ncsa-security-all-fork](https://github.com/ttomttom/ncsa-security-all-fork)
2. [myproxy-fork](https://github.com/ttomttom/myproxy-fork)

## Other Resources

If you're looking for an example portal (the clinet which is talking to the Master Portal)  implmentation check out the [vo-portal](https://github.com/ttomttom/aarc-vo-portal)

If you're looking for the the Delegation Server implementation (the server to which the Master Portal is talking to) implementation check out the [delegation-server](https://github.com/ttomttom/aarc-delegation-server)
