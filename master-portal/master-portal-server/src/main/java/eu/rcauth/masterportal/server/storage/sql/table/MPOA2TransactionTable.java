package eu.rcauth.masterportal.server.storage.sql.table;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionTable;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;

import java.sql.Types;

import eu.rcauth.masterportal.server.storage.MPOA2TransactionKeys;

public class MPOA2TransactionTable extends OA2TransactionTable {

    public MPOA2TransactionTable(OA2TransactionKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry( ((MPOA2TransactionKeys)getOA2Keys()).claims(),
                                                             Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry( ((MPOA2TransactionKeys)getOA2Keys()).mp_client_session_identifier(),
                                                             Types.LONGVARCHAR));
    }
}
