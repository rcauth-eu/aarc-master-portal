package edu.uiuc.ncsa.security.oauth_2_0.client;

import edu.uiuc.ncsa.security.delegation.client.server.AGServer;
import edu.uiuc.ncsa.security.delegation.client.server.ATServer;
import edu.uiuc.ncsa.security.delegation.client.server.PAServer;
import edu.uiuc.ncsa.security.delegation.client.server.RTServer;
import edu.uiuc.ncsa.security.delegation.client.request.*;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.oauth_2_0.client.DS2;

import java.util.Map;

public class ProxyDelegationService extends DS2 {

    public ProxyDelegationService(AGServer agServer, ATServer atServer, PAServer paServer, UIServer2 uiServer, RTServer rtServer, PAServer ppServer) {
        super(agServer, atServer, paServer, uiServer, rtServer);
        this.ppServer = ppServer;
    }
	
    protected PAServer ppServer;
    
    public PAServer getPPServer() {
		return ppServer;
	}
    
    
    public DelegatedAssetResponse getProxy(ATResponse atResponse, Client client, Map<String, String> assetParameters) {
        PPRequest ppReq = new PPRequest();
        ppReq.setClient(client);
        ppReq.setAccessToken(atResponse.getAccessToken());
        ppReq.setParameters(assetParameters);
        PPResponse ppResp = (PPResponse) getPPServer().process(ppReq);
        DelegatedAssetResponse dap = new DelegatedAssetResponse(ppResp.getProtectedAsset());
        dap.setAdditionalInformation(ppResp.getAdditionalInformation());
        return dap;
    }	

}
