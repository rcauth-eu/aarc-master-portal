# aarc-portal

This is a custom [OA4MP](http://grid.ncsa.illinois.edu/myproxy/oauth/client/manuals/getting-started.xhtml)
implemetation for AARC [Pre-Piloting Work](https://wiki.nikhef.nl/grid/CILogon_Pre-Pilot_Work#Master_Portal).

**NOTE** *This is software is still in its piloting phase, and it's in no way meant to be used as a production
ready component!*

## Structure 

This repository contains the implementation if the following two components:

### VO Portal

The VO Portal is a modified OA4MP Client. The VO Portal has only been developed for demonstration purposes 
and only servs as a proof of concept. It simply connects to a Master Portal, retrieves a proxy for the 
authenticated user, and displays it in the browser. A more practical implementation of the VO Portal would take
the retrieved proxy and use it to authenticate the user for further operations (depending on usecase).

### Master Portal

The Master Portal is both a OA4MP Client and a Server. For the purpse of the VO Portal, the Master Portal is
an OA4MP Server. For the purpose of the Delegation Service the Master Portal is an OA4MP Client. The Master
Portal caches long lived user proxies into its MyProxy Crendential Store, and returns short lived proxies 
on demand for authenricated users via the VO Portal. 

## Building

In case you wish the build the Master Portal or VO Portal you should first build two of its dependencies in the
following order 

1. [ncsa-security-all-fork](https://github.com/ttomttom/ncsa-security-all-fork)
2. [myproxy-fork](https://github.com/ttomttom/myproxy-fork)


