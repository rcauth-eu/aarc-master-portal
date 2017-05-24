package org.masterportal.oauth2.server.storage.sql.table;

import org.masterportal.oauth2.server.storage.SSHKeyKeys;

import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import static java.sql.Types.VARCHAR;
import static java.sql.Types.INTEGER;
import static java.sql.Types.TIMESTAMP;

public class SSHKeyTable extends Table {
    private final String TIME_LABEL = "import_time";


    public SSHKeyTable(SSHKeyKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }
	
    @Override
    public void createColumnDescriptors() {
//    	super.createColumnDescriptors();
    	SSHKeyKeys x =  (SSHKeyKeys) keys;

	// We will be using the pair username,label as a composite primary key

	// label must be only unique per user, so not primary, must be present
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.label(), VARCHAR, false, false));

	// username can have multiple keys, so do not declare primary, must be present
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.username(), VARCHAR, false, false));

	// pubkey must be unique for ssh, also must be present, but don't make
	// it present as we want to be able to change it
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.pub_key(), VARCHAR, false, false));
	
	// description is optional
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.description(), VARCHAR));

	// Don't create TIMESTAMP row, since it will fail with the
	// getColumnDescriptor() used in e.g. creation e.g. in
	// createRegisterStatement() in createInsertStatement() below and also
	// in createUpdateStatement(). Unfortunately, table creation does not
	// order the rows...
    }

    /**
     * Creates statement to obtain all entries ordered by username,label
     */
    public String createAllSelectStatement(){
        SSHKeyKeys x =  (SSHKeyKeys) keys;
    	String select =  "SELECT * FROM " + getFQTablename();

        select += " ORDER BY "+x.username()+","+x.label()+" ASC";
        
        return select;
    }


    /**
     * Creates statement to obtain all entries for a single username
     */
    public String createUserSelectStatement(){
        SSHKeyKeys x =  (SSHKeyKeys) keys;
    	String select =  "SELECT * FROM " + getFQTablename() + " WHERE ";

	select += x.username() + " =?";
        
	select += " ORDER BY "+x.label()+" ASC";

        return select;
    }    
    
    /**
     * Creates statement to obtain a specific key
     */
    public String createKeySelectStatement(){
        SSHKeyKeys x =  (SSHKeyKeys) keys;
    	String select =  "SELECT * FROM " + getFQTablename() + " WHERE ";

	select += x.pub_key() + " =?";
        
        return select;
    }    
    
    /**
     * Creates the select statement for this table based on user/label, which
     * should be the composite primary key
     */
    @Override
    public String createSelectStatement(){
        SSHKeyKeys x =  (SSHKeyKeys) keys;
    	String select =  "SELECT * FROM " + getFQTablename() + " WHERE ";

	select += x.username() + " =? AND " + x.label() + " =? ";

        return select;
    }

    /**
     * Creates update statement for (username,label) pair
     */
    @Override
    public String createUpdateStatement() {
	SSHKeyKeys x =  (SSHKeyKeys) keys;

        String update = "UPDATE " + getFQTablename() + " SET ";

        boolean isFirst = true;
        for (ColumnDescriptorEntry cde : getColumnDescriptor()) {
	    String name = cde.getName();
	    if (!name.equals(x.username()) && !name.equals(x.label())) {
		update = update + (isFirst ? "" : ", ") + name + "=?";
		if (isFirst) {
		    isFirst = false;
		}   
            }        	
        }

        update += ", "+TIME_LABEL+"=CURRENT_TIMESTAMP";
        
        String where = " WHERE " + x.username() + " =? " +
		       " AND " + x.label() + " =? ";
        
        return update + where;
    }

    /**
     * Creates delete statement for (username,label) pair
     */
    public String createDeleteStatement() {
	SSHKeyKeys x =  (SSHKeyKeys) keys;

        String delete = "DELETE FROM " + getFQTablename() +
			" WHERE " + x.username() + " =? " +
		        " AND " + x.label() + " =? ";
        
        return delete;
    }

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
