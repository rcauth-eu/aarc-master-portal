# aarc-master-portal

This is a custom [OA4MP](http://grid.ncsa.illinois.edu/myproxy/oauth/client/manuals/getting-started.xhtml)
implementation for AARC [Pre-Piloting Work](https://wiki.nikhef.nl/grid/AARC_Pilot) in particular for the
[Master Portal](https://wiki.nikhef.nl/grid/Master_Portal_Internals)

## Master Portal

The Master Portal is both an OA4MP Client and a Server. From the perspective of
the VO Portal, the Master Portal is an OA4MP Server. From the perspective of the
Delegation Service the Master Portal is an OA4MP Client. The Master Portal
caches long lived user proxies into its backend MyProxy Crendential Store, and
returns short lived proxies on demand for authenticated users via the VO Portal. 

## Building

In case you wish the build the Master Portal you should first build two of its
dependencies in the following order 

1. [security-lib](https://github.com/rcauth-eu/security-lib)
2. [OA4MP](https://github.com/rcauth-eu/OA4MP)

See [AARC Pilot - Building from Source](https://wiki.nikhef.nl/grid/AARC_Pilot_-_Building_from_Source) for further details.

## Other Resources

If you're looking for an example portal (the client which is talking to the
Master Portal) implementation check out the
[vo-portal](https://github.com/rcauth-eu/aarc-vo-portal) or have a look at the
[demo site](http://rcdemo.nikhef.nl/).

If you're looking for the the Delegation Server implementation (the server to
which the Master Portal is talking to) implementation check out the
[delegation-server](https://github.com/rcauth-eu/aarc-delegation-server).
