package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.RetentionPolicy;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;

import java.util.Date;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/26/14 at  3:39 PM
 */
public class RefreshTokenRetentionPolicy implements RetentionPolicy {
    public RefreshTokenRetentionPolicy(RefreshTokenStore rts) {
        this.rts = rts;
    }

    RefreshTokenStore rts;

    /**
     * Always true for every element in the cache.
     * @return
     */
    @Override
    public boolean applies() {
        return true;
    }

    @Override
    public boolean retain(Object key, Object value) {
        Identifier identifier = (Identifier) key;
        OA2ServiceTransaction st2 = (OA2ServiceTransaction)value;
        RefreshToken rt = st2.getRefreshToken();
        if(rt == null || rt.getToken()== null){
            return true;
        }
        // Now we have to check against the timestamp on the original and the expires in flag.
         Date creationTS = DateUtils.getDate(st2.getRefreshToken().getToken());

        if(creationTS.getTime() + st2.getRefreshTokenLifetime() <= System.currentTimeMillis()){
            return true;
        }
        return false;
    }

    @Override
    public Map getMap() {
        return rts;
    }
}
