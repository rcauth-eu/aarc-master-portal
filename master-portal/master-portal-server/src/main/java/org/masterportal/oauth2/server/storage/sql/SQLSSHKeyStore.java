package org.masterportal.oauth2.server.storage.sql;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.inject.Provider;

import org.masterportal.oauth2.server.storage.SSHKey;
import org.masterportal.oauth2.server.storage.SSHKeyStore;
import org.masterportal.oauth2.server.storage.sql.table.SSHKeyTable;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import static java.sql.Types.LONGVARCHAR;

public class SQLSSHKeyStore extends SQLStore<SSHKey> implements SSHKeyStore<SSHKey> {
    public static final String DEFAULT_TABLENAME = "ssh_keys";

    private static final String USERNAME_COLUMN =   "username";
    private static final String LABEL_COLUMN =	    "label";

	
    public SQLSSHKeyStore(ConnectionPool connectionPool,
            Table table,
            Provider<SSHKey> identifiableProvider,
            MapConverter converter) {
    	super(connectionPool, table, identifiableProvider, converter);
    }

    /**
     * Get all entries in the DB
     */
    public List<SSHKey> getAll()    {
	Connection c = getConnection();
	List<SSHKey> resultSet = new ArrayList<SSHKey>();
	try {
	    PreparedStatement stmt = c.prepareStatement( ((SSHKeyTable)getTable()).createAllSelectStatement() );
	    stmt.executeQuery();
	    ResultSet rs = stmt.getResultSet();
	    
	    // iterate over result set
	    while ( rs.next() ) {
		ColumnMap map = rsToMap(rs);
		SSHKey t = create();
		populate(map, t);
		resultSet.add(t);
	    }
	    rs.close();
	    stmt.close();
	} catch (SQLException e) {
	    destroyConnection(c);
	    throw new GeneralException("Error getting SSH keys", e);
	} finally {
	    releaseConnection(c);
	}

	if ( resultSet.isEmpty() ) {
	    return null;
	} 
	
	return resultSet;
    }

    /**
     * Get all entries in the DB for given username
     */
    public List<SSHKey> getAll(String username)    {
	Connection c = getConnection();
	List<SSHKey> resultSet = new ArrayList<SSHKey>();
	try {
	    PreparedStatement stmt = c.prepareStatement( ((SSHKeyTable)getTable()).createUserSelectStatement());
	    stmt.setString(1, username);

	    stmt.executeQuery();
	    ResultSet rs = stmt.getResultSet();
	    
	    // iterate over result set
	    while ( rs.next() ) {
		ColumnMap map = rsToMap(rs);
		SSHKey t = create();
		populate(map, t);
		resultSet.add(t);
	    }
	    rs.close();
	    stmt.close();
	} catch (SQLException e) {
	    destroyConnection(c);
	    throw new GeneralException("Error getting SSH keys for " + username, e);
	} finally {
	    releaseConnection(c);
	}

	if (  resultSet.isEmpty() ) {
	    return null;
	} 
	
	return resultSet;
    }

    /**
     * Adds key to the username
     */
    @Override
    public void save(SSHKey value)  {
	/* Just a wrapper around register */
	register(value);
    }

    /**
     * Adds key to the username
     */
    @Override
    public void register(SSHKey value) {
        Connection c = getConnection();

	try {
	    String tableName = getTable().getTablename();
	    ResultSet res = c.getMetaData().getTables(null, null, tableName, new String[] {"TABLE"});
	    if (res.next() == false)    {
		throw new GeneralException("Cannot find table "+tableName);
	    }

	    SSHKeyTable table = (SSHKeyTable)getTable();
            PreparedStatement stmt = c.prepareStatement( table.createInsertStatement() );
            ColumnMap map = depopulate(value);
            int i = 1;
            for (ColumnDescriptorEntry cde : table.getColumnDescriptor()) {
                // now we loop through the table and set each and every one of these
                // OAUTH-148 fix: MariaDB driver does not accept longvarchar as a type in setObject (known bug for
                // them. Workaround is to explicitly test for this and carry out a setString call instead.
                if (cde.getType() == LONGVARCHAR) {
                    Object obj = map.get(cde.getName());
                    stmt.setString(i++, obj == null ? null : obj.toString());
                } else {
                    stmt.setObject(i++, map.get(cde.getName()), cde.getType());
                }
            }
            stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content of x as per JDBC spec.
            stmt.close();
        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error registering entry for username=" + value.getUserName() + " label=" + value.getLabel(), e);
        } finally {
            releaseConnection(c);
        }
    }

    /**
     * Overrides update(V ) in SQLStore, implements update(SSHKey in SQLSSHKeyStore
     */
    @Override
    public void update(SSHKey value) {
        Connection c = getConnection();
        try {
	    SSHKeyTable table = (SSHKeyTable)getTable();
            PreparedStatement stmt = c.prepareStatement( table.createUpdateStatement() );
            ColumnMap map = depopulate(value);
            int i = 1;
            for (ColumnDescriptorEntry cde : table.getColumnDescriptor()) {
                // now we loop through the table and set each and every one of these
		String name = cde.getName();
		// Only can update the non-username, non-label entries
                if (!name.equals(USERNAME_COLUMN) && !name.equals(LABEL_COLUMN)) {
                    Object obj = map.get(name);
                    // Dates confuse setObject, so turn it into an SQL Timestamp object.
                    if (obj instanceof Date) {
                        obj = new Timestamp(((Date) obj).getTime());
                    }
                    if (obj instanceof BasicIdentifier) {
                        stmt.setString(i++, obj.toString());
                    } else {
                        stmt.setObject(i++, obj);
                    }
                }
            }

            // now set the matching keys: userName and label
            stmt.setString(i++, value.getUserName());
            stmt.setString(i++, value.getLabel());
            
            stmt.executeUpdate();
            stmt.close();

        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error updating entry for username=" + value.getUserName() + " label=" + value.getLabel(), e);
        } finally {
            releaseConnection(c);
        }
		
    }

    /**
     * Overrides get() in SQLStore
     */
    @Override
    public SSHKey get(Object key) {
	if ( !(key instanceof SSHKey) ) {
            throw new GeneralException("input key must be a SSHKey");
	}
	SSHKey value = (SSHKey) key;
	SSHKey out = null;

        Connection c = getConnection();
        try {
	    PreparedStatement stmt = c.prepareStatement( ((SSHKeyTable)getTable()).createSelectStatement() );
            stmt.setString(1, value.getUserName());
            stmt.setString(2, value.getLabel());

	    stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content of x as per JDBC spec.
	    ResultSet rs = stmt.getResultSet();
	    if (rs.next())  {	// Need to move to the first element (if available)
		ColumnMap map = rsToMap(rs);
		out = create();
		populate(map, out);
	    }
	    rs.close();
            stmt.close();
        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error getting key", e);
        } finally {
            releaseConnection(c);
        }
        return out;
    }

    /**
     * Overrides remove() in SQLStore
     */
    @Override
    public SSHKey remove(Object key) {
	if ( !(key instanceof SSHKey) ) {
            throw new GeneralException("input key must be a SSHKey");
	}
	SSHKey value = (SSHKey)key;
	SSHKey oldObject = null;
        try {
            oldObject = get(value);
        } catch (GeneralException x) {
            return null;
        }

        Connection c = getConnection();
        try {
	    PreparedStatement stmt = c.prepareStatement( ((SSHKeyTable)getTable()).createDeleteStatement() );
            stmt.setString(1, value.getUserName());
            stmt.setString(2, value.getLabel());
            stmt.execute();
            stmt.close();
        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error removing key", e);
        } finally {
            releaseConnection(c);
        }
        return oldObject;
    }

    /**
     * Returns whether the pubkey already exists
     * Overrides containsKey() in SQLStore
     */
    @Override
    public boolean containsKey(Object key) {
	if ( !(key instanceof SSHKey) ) {
            throw new GeneralException("input key must be a SSHKey");
	}
	SSHKey value = (SSHKey) key;
	    
	Connection c = getConnection();
	boolean rc = false;
	try {
	    PreparedStatement stmt = c.prepareStatement( ((SSHKeyTable)getTable()).createKeySelectStatement() );
	    stmt.setString(1, value.getPubKey());
	    stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content of x as per JDBC spec.
	    ResultSet rs = stmt.getResultSet();
	    rc = rs.next();
	    rs.close();
	    stmt.close();
	} catch (SQLException e) {
	    destroyConnection(c);
	    e.printStackTrace();
	} finally {
	    releaseConnection(c);
	}
	return rc;		
    }
}
