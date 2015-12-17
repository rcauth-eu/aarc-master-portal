package edu.uiuc.ncsa.myproxy.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;
import junit.framework.TestCase;
import org.junit.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;

/**
 * Basic testing of the asset store implementations.
 * <p>Created by Jeff Gaynor<br>
 * on 1/29/13 at  11:53 AM
 */
public class AssetStoreTest extends TestCase {


    @Test
    public void testAsset() throws Exception {
        Identifier id = BasicIdentifier.newID("asset:id:/" + ClientTestStoreUtil.getRandomString());
        Asset asset = new Asset(id);
        PrivateKey privateKey = KeyUtil.generateKeyPair().getPrivate();
        String username = "testUser-" + ClientTestStoreUtil.getRandomString(8);
        URI redirect = URI.create("http://test.foo/test" + ClientTestStoreUtil.getRandomString(8));
        asset.setPrivateKey(privateKey);
        asset.setUsername(username);
        asset.setRedirect(redirect);


        assert asset.getPrivateKey().equals(privateKey);
        assert asset.getUsername().equals(username);
        assert asset.getRedirect().equals(redirect);

    }

    /**
     * This returns an asset so subclasses can add their own tests for extensions to the asset.
     *
     * @param store
     * @return
     * @throws Exception
     */
    public Asset storeTest(AssetStore store) throws Exception {
        if (store == null) {
            System.out.println("WARNING: no asset store configured, skipping test.");
            return null;
        }
        Identifier id = BasicIdentifier.newID("asset:id:/" + System.currentTimeMillis());

        Asset asset = store.create();
        asset.setIdentifier(id);
        assert asset != null : "Error: The store is not producing valid assets when requested. A null was returned";
        KeyPair kp = KeyUtil.generateKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        MyPKCS10CertRequest cr = CertUtil.createCertRequest(kp);
        String rawCR = CertUtil.fromCertReqToString(cr);
        String username = "testUser";
        URI redirect = URI.create("http://test.foo/test" + System.currentTimeMillis());

        asset.setPrivateKey(privateKey);
        asset.setUsername(username);
        asset.setRedirect(redirect);
        asset.setCertReq(cr);

        store.save(asset);

        // now read it back.
        Asset asset2 = store.get(id);

        assert asset.getIdentifier().equals(asset2.getIdentifier()) : "Identifiers on assets do nto match. " +
                "Expected \"" + asset.getIdentifierString() + "\" but got \"" + asset2.getIdentifierString() + "\"";
        assert asset.getUsername().equals(asset2.getUsername()) : "Username on assets do not match. " +
                "Expected \"" + asset.getUsername() + "\" but got \"" + asset2.getUsername();
        assert asset.getPrivateKey().equals(asset2.getPrivateKey()) : "Private keys on assets do not match. " +
                "Expected \"" + asset.getPrivateKey() + "\" but got \"" + asset2.getPrivateKey();
        assert asset.getRedirect().equals(asset2.getRedirect()) : "Redirect on assets do not match. " +
                "Expected \"" + asset.getRedirect() + "\" but got \"" + asset2.getRedirect();
        // Special note: MySQL will truncate nanoseconds from dates so the best we can do is verify the milliseconds match.
        assert Math.abs(asset.getCreationTime().getTime() - asset2.getCreationTime().getTime())<1000 : "Timestamp on assets do not match. " +
                "Expected \"" + asset.getCreationTime() + "\" but got \"" + asset2.getCreationTime() + "\"";
        // Generally there is no good concept of equality between certificatiion requests. In this specific case though,
        // the requests should be identical so we can compare them as strings. This is a data integrity test.
        assert rawCR.equals(CertUtil.fromCertReqToString(asset2.getCertReq())) : "Certification requests on assets do not match. " +
                  "Expected \"" + asset.getCertReq() + "\" but got \"" + asset2.getCertReq();

        return asset;
    }

    @Test
    public void testMemoryStore() throws Exception {
        storeTest(ClientTestStoreUtil.getMemoryStore());
    }

    @Test
    public void testFileStore() throws Exception {
        storeTest(ClientTestStoreUtil.getFileStore());
    }


    @Test
    public void testPGStore() throws Exception {
        storeTest(ClientTestStoreUtil.getPostgresStore());
    }

    @Test
    public void testMySQLStore() throws Exception {
        storeTest(ClientTestStoreUtil.getMysqlStore());
    }
}
