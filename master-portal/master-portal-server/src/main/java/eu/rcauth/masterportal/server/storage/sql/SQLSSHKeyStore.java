package eu.rcauth.masterportal.server.storage.sql;

import edu.uiuc.ncsa.security.core.Identifiable;
import eu.rcauth.masterportal.server.storage.SSHKey;
import eu.rcauth.masterportal.server.storage.SSHKeyKeys;
import eu.rcauth.masterportal.server.storage.SSHKeyStore;
import eu.rcauth.masterportal.server.storage.sql.table.SSHKeyTable;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static java.sql.Types.LONGVARCHAR;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 * Main and SQL-based implementation of a {@link SSHKeyStore}.
 */
public class SQLSSHKeyStore extends SQLStore<SSHKey> implements SSHKeyStore<SSHKey> {
    /** SQL table name for the SSH Keys */
    public static final String DEFAULT_TABLENAME = "ssh_keys";


    public SQLSSHKeyStore(ConnectionPool connectionPool,
            Table table,
            Provider<SSHKey> identifiableProvider,
            MapConverter<SSHKey> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    /**
     * @return List of all {@link SSHKey} entries in the DB for given username
     */
    @Override
    public List<SSHKey> getAll(String username)    {
        Connection c = getConnection();
        List<SSHKey> resultSet = new ArrayList<>();
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

        // Even return resultSet if it is an empty set
        return resultSet;
    }

    /**
     * Adds key to the specified username, currently just a wrapper around
     * {@link #register(SSHKey)}.
     */
    @Override
    public void save(SSHKey value)  {
        register(value);
    }

    /**
     * Adds key to the specified username. The is an adapted version of
     * {@link SQLStore#register(Identifiable)} that is based on a single-field Identifier.
     */
    @Override
    public void register(SSHKey value) {
        Connection c = getConnection();

        try {
            String tableName = getTable().getTablename();
            ResultSet res = c.getMetaData().getTables(null, null, tableName, new String[] {"TABLE"});
            if ( !res.next() )
                throw new GeneralException("Cannot find table "+tableName);

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
     * Overrides {@link SQLStore#update(Identifiable)}, implements {@link
     * SSHKeyStore#update(SSHKey)}. We need to override since we use two columns
     * for identification instead of one.
     */
    @Override
    public void update(SSHKey value) {
        Connection c = getConnection();
        // Get the column headers
        SSHKeyKeys sshKeyKeys = new SSHKeyKeys();
        String userNameColumn = sshKeyKeys.userName();
        String labelColumn = sshKeyKeys.label();
        try {
            SSHKeyTable table = (SSHKeyTable)getTable();
            PreparedStatement stmt = c.prepareStatement( table.createUpdateStatement() );
            ColumnMap map = depopulate(value);
            int i = 1;
            for (ColumnDescriptorEntry cde : table.getColumnDescriptor()) {
                // now we loop through the table and set each and every one of these
                String name = cde.getName();
                // Only can update the non-username, non-label entries
                if (!name.equals(userNameColumn) && !name.equals(labelColumn)) {
                    Object obj = map.get(name);
                    // Dates confuse setObject, so turn it into an SQL Timestamp object.
                    if (obj instanceof Date) {
                        obj = new Timestamp(((Date) obj).getTime());
                    }

                    if (obj instanceof BasicIdentifier)
                        stmt.setString(i++, obj.toString());
                    else
                        stmt.setObject(i++, obj);
                }
            }

            // now set the matching keys: userName and label
            stmt.setString(i++, value.getUserName());
            stmt.setString(i, value.getLabel()); // Note: when we add more, change i -> i++ here

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
     * Overrides {@link SQLStore#get(Object)}.
     * We need to override since we use two columns for identification instead
     * of one.
     */
    @Override
    public SSHKey get(Object key) {
        if ( !(key instanceof SSHKey) )
            throw new GeneralException("input key must be a SSHKey");

        SSHKey value = (SSHKey) key;
        SSHKey out = null;

        Connection c = getConnection();
        try {
            SSHKeyTable table = (SSHKeyTable)getTable();
            PreparedStatement stmt = c.prepareStatement( table.createSelectStatement() );
            stmt.setString(1, value.getUserName());
            stmt.setString(2, value.getLabel());

            stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content of x as per JDBC spec.
            ResultSet rs = stmt.getResultSet();
            if (rs.next())  { // Need to move to the first element (if available)
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
     * Overrides {@link SQLStore#remove(Object)}.
     * We need to override since we use two columns for identification instead
     * of one.
     */
    @Override
    public SSHKey remove(Object key) {
        if ( !(key instanceof SSHKey) )
            throw new GeneralException("input key must be a SSHKey");

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
     * Returns whether the pubKey in key already exists.
     * Overrides {@link SQLStore#containsKey(Object)}.
     */
    @Override
    public boolean containsKey(Object key) {
        if ( !(key instanceof SSHKey) )
            throw new GeneralException("input key must be a SSHKey");

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
