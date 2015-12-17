package test;

import java.io.BufferedInputStream;
import java.io.FileInputStream;

import org.voportal.voms.VPBufferedMessageLogger;
import org.voportal.voms.VPVomsProxyInfo;

public class ProxyVomsInfoCLITester {

	public static void main(String[] args) throws Exception {
		
		String s = VPVomsProxyInfo.exec("/tmp/test.proxy");
		System.out.println(s);
	}

}
