package eu.rcauth.masterportal.server.storage;

import eu.rcauth.masterportal.server.MPOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;

import net.sf.json.JSONObject;

public class MPOA2TConverter<V extends MPOA2ServiceTransaction> extends OA2TConverter<V> {

    public MPOA2TConverter(MPOA2TransactionKeys keys, IdentifiableProvider<V> identifiableProvider, TokenForge tokenForge, ClientStore<? extends Client> cs) {
        super(keys, identifiableProvider, tokenForge, cs);
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V st = super.fromMap(map, v);

        MPOA2TransactionKeys tck = (MPOA2TransactionKeys) getTCK();

        st.setMPClientSessionIdentifier( map.getString(tck.mp_client_session_identifier) );

        String jsonClaims = map.getString(tck.claims);
        if ( jsonClaims != null && !jsonClaims.isEmpty() )
            st.setClaims( JSONObject.fromObject(jsonClaims) );

        return st;
    }


    @Override
    public void toMap(V t, ConversionMap<String, Object> map) {
        super.toMap(t, map);

        MPOA2TransactionKeys tck = (MPOA2TransactionKeys) getTCK();

        String clientSessionID = t.getMPClientSessionIdentifier();
        if (clientSessionID != null && !clientSessionID.isEmpty())
            map.put(tck.mp_client_session_identifier, clientSessionID);

        JSONObject claims = t.getClaims();
        if ( claims != null ) {
            // Note: t.getClaims returns a JSONObject, need to put it as a
            // String in the map, or fromMap() above cannot parse it.
            map.put( tck.claims , claims.toString() );
        }
    }

}
