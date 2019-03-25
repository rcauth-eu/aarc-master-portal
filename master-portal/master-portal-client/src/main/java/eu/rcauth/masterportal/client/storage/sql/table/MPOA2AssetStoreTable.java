package eu.rcauth.masterportal.client.storage.sql.table;

import static java.sql.Types.LONGVARCHAR;

import eu.rcauth.masterportal.client.storage.MPOA2AssetSerializationKeys;

import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetSerializationKeys;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2AssetStoreTable;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;

public class MPOA2AssetStoreTable extends OA2AssetStoreTable {

    public MPOA2AssetStoreTable(AssetSerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }
    
    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        
        MPOA2AssetSerializationKeys extendedKeys = (MPOA2AssetSerializationKeys) keys;

        getColumnDescriptor().add(new ColumnDescriptorEntry(extendedKeys.mp_server_request_code(), LONGVARCHAR, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(extendedKeys.mp_server_request_state(), LONGVARCHAR, true, false));
    }
    
}
