package org.voportal.client;

import java.security.PrivateKey;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;

public class ProxyAssetResponse extends AssetResponse {

	protected PrivateKey proxyKey;
	protected byte[] proxy;
	
	public byte[] getProxy() {
		return proxy;
	}
	
	public PrivateKey getProxyKey() {
		return proxyKey;
	}
	
	public void setProxy(byte[] proxy) {
		this.proxy = proxy;
	}
	
	public void setProxyKey(PrivateKey proxyKey) {
		this.proxyKey = proxyKey;
	}
	
}
