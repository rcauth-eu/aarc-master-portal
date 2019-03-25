package eu.rcauth.masterportal.server.storage.sql.table;

import eu.rcauth.masterportal.server.storage.SSHKeyKeys;

import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import static java.sql.Types.VARCHAR;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 * Class implementing (primarily) methods to obtain the SQL prepared statements
 * for interacting with the {@link SQLSSHKeyStore}
 */
public class SSHKeyTable extends Table {
    /** SQL table header for the timestamp column */
    private final String TIME_LABEL = "import_time";


    public SSHKeyTable(SSHKeyKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    /**
     * Adds column descriptors for the label, userName, pubKey and description
     * columns.
     */
    @Override
    public void createColumnDescriptors() {
//    	super.createColumnDescriptors();
    	SSHKeyKeys x =  (SSHKeyKeys) keys;

	// We will be using the pair userName,label as a composite primary key

	// label must be only unique per user, so not primary, must be present
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.label(), VARCHAR, false, false));

	// userName can have multiple keys, so do not declare primary, must be present
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.userName(), VARCHAR, false, false));

	// pubkey must be unique for ssh, also must be present, but don't make
	// it present as we want to be able to change it
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.pubKey(), VARCHAR, false, false));
	
	// description is optional
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.description(), VARCHAR));

	// Don't create TIMESTAMP row, since it will fail with the
	// getColumnDescriptor() used in e.g. creation e.g. in
	// createRegisterStatement() in createInsertStatement() below and also
	// in createUpdateStatement(). Unfortunately, table creation does not
	// order the rows...
    }

    /**
     * Creates SQL select statement to obtain all entries for a single username.
     */
    public String createUserSelectStatement(){
        SSHKeyKeys x =  (SSHKeyKeys) keys;
    	String select =  "SELECT * FROM " + getFQTablename() + " WHERE ";

	select += x.userName() + " =?";
        
	select += " ORDER BY "+x.importTime()+" DESC";

        return select;
    }    
    
    /**
     * Creates SQL select statement for a specific pubKey.
     */
    public String createKeySelectStatement(){
        SSHKeyKeys x =  (SSHKeyKeys) keys;
    	String select =  "SELECT * FROM " + getFQTablename() + " WHERE ";

	select += x.pubKey() + " =?";
        
        return select;
    }    
    
    /**
     * Creates SQL select statement for (userName/label) pair, which should be
     * the composite primary key.
     */
    @Override
    public String createSelectStatement(){
        SSHKeyKeys x =  (SSHKeyKeys) keys;
    	String select =  "SELECT * FROM " + getFQTablename() + " WHERE ";

	select += x.userName() + " =? AND " + x.label() + " =? ";

        return select;
    }

    /**
     * Creates SQL update statement for (userName,label) pair, which should be
     * the composite primary key.
     */
    @Override
    public String createUpdateStatement() {
	SSHKeyKeys x =  (SSHKeyKeys) keys;

        String update = "UPDATE " + getFQTablename() + " SET ";

        boolean isFirst = true;
        for (ColumnDescriptorEntry cde : getColumnDescriptor()) {
	    String name = cde.getName();
	    if (!name.equals(x.userName()) && !name.equals(x.label())) {
		update = update + (isFirst ? "" : ", ") + name + "=?";
		if (isFirst) {
		    isFirst = false;
		}   
            }        	
        }

        update += ", "+TIME_LABEL+"=CURRENT_TIMESTAMP";
        
        String where = " WHERE " + x.userName() + " =? " +
		       " AND " + x.label() + " =? ";
        
        return update + where;
    }

    /**
     * Creates SQL delete statement for (userName,label) pair, which should be
     * the composite primary key.
     */
    public String createDeleteStatement() {
	SSHKeyKeys x =  (SSHKeyKeys) keys;

        String delete = "DELETE FROM " + getFQTablename() +
			" WHERE " + x.userName() + " =? " +
		        " AND " + x.label() + " =? ";
        
        return delete;
    }

    /**
     * Creates SQL insert statement for complete set of values (userName, label,
     * pubKey and description).
     */
    @Override
    public String createInsertStatement() {
        String out = "INSERT INTO " + getFQTablename() + "(" + createRegisterStatement() + ", " + TIME_LABEL+ ") VALUES (" ;
        String qmarks = "";
        for (int i = 0; i < getColumnDescriptor().size(); i++) {
            qmarks = qmarks + "?" + (i + 1 == getColumnDescriptor().size() ? "" : ", ");
        }
        qmarks += ",CURRENT_TIMESTAMP";
        
        out = out + qmarks + ")";
        return out;
    }
    
}
