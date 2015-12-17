package edu.uiuc.ncsa.security.storage.sql;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.cache.SimpleEntryImpl;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptors;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;
import java.lang.reflect.Field;
import java.sql.*;
import java.util.*;
import java.util.Date;

/**
 * Top-level SQL store object. A store is simply a logical analog of a hash table, where the key
 * is the primary key. This in practice may front multiple tables. This implements several of the
 * basic operations. You need to implement a couple of methods and supply a {@link Table} that models the
 * storage and a {@link MapConverter} that allows you to turn a java object's properties into
 * a map -- then you should be in business for using an SQL backend.
 * All of these statements are SQL 2003 compliant and should work without change for all major vendors.
 * This class also maintains a connection pool to a database.
 * <p>Created by Jeff Gaynor<br>
 * on Mar 12, 2010 at  12:58:14 PM
 */
public abstract class SQLStore<V extends Identifiable> extends SQLDatabase implements Store<V> {
    protected SQLStore(ConnectionPool connectionPool,
                       Table table,
                       Provider<V> identifiableProvider,
                       MapConverter<V> converter) {
        super(connectionPool);
        this.table = table;
        this.identifiableProvider = identifiableProvider;
        this.converter = converter;
    }


    protected Provider<V> identifiableProvider;

    public SQLStore() {
    }

    @Override
    public V create() {
        return (V) identifiableProvider.get();
    }

    protected MapConverter<V> converter;


    /**
     * For an existing entry in the store. This will select it based on the primary key
     * and change all other values.
     *
     * @param value
     */
    public void update(V value) {

        if (!containsValue(value)) {
            throw new GeneralException("Error: cannot update non-existent entry for\"" +
                    value.getIdentifierString() + "\". Register it first or call save.");
        }
        Connection c = getConnection();
        try {

            PreparedStatement stmt = c.prepareStatement(getTable().createUpdateStatement());
            ColumnMap map = depopulate(value);
            int i = 1;
            for (ColumnDescriptorEntry cde : getTable().getColumnDescriptor()) {
                // now we loop through the table and set each and every one of these
                if (!cde.isPrimaryKey()) {
                    Object obj = map.get(cde.getName());
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

            // now set the primary key
            stmt.setString(i++, value.getIdentifierString());
            stmt.executeUpdate();
            stmt.close();

        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error updating approval with identifier = \"" + value.getIdentifierString(), e);
        } finally {
            releaseConnection(c);
        }
    }


    /**
     * Take a *new* value and populate it from the given mapping of column names and values.
     * All values must be accounted for since
     * the result set generally will come from a <code> SELECT * FROM... </code>
     *
     * @param map
     * @param t
     */
    public void populate(ColumnMap map, V t) {
        converter.fromMap(map, t);
    }


    /**
     * Takes the object, V and returns a map of column name, value. This is used to construct various statements
     * This is where the columns and object properties are put in correspondence. We could try to do this with some
     * sort of introspection, but that is very, very slow and not always clear on how it should be done.
     *
     * @param t
     * @return
     * @throws SQLException
     */
    public ColumnMap depopulate(V t) throws SQLException {
        ColumnMap map = new ColumnMap();
        converter.toMap(t, map);
        return map;
    }


    public void save(V value) {
        if (containsKey(value.getIdentifier())) {
            update(value);
        } else {
            register(value);
        }
    }

    public void register(V value) {
        Connection c = getConnection();
        try {
            PreparedStatement stmt = c.prepareStatement(getTable().createInsertStatement());
            Map<String, Object> map = depopulate(value);
            int i = 1;
            for (ColumnDescriptorEntry cde : getTable().getColumnDescriptor()) {
                // now we loop through the table and set each and every one of these
                // OAUTH-148 fix: MariaDB driver does not accept longvarchar as a type in setObject (known bug for
                // them. Workaround is to explicitly test for this and carry out a setString call instead.
                if (cde.getType() == Types.LONGVARCHAR) {
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
            throw new GeneralException("Error: could not register object with id \"" + value.getIdentifierString() + "\"", e);
        } finally {
            releaseConnection(c);
        }
    }

    /**
     * Retrieve a single row from a table then populate an instance. <br/>
     * Note: If you need to jazz this up, it is probably better to override the {@link #rsToMap(java.sql.ResultSet)}
     * method in this class. For instance, if the select statement is a join and there are multiple rows to
     * process. The basic version of this class presupposed one row per object, but there is no reason this
     * cannot be extended.
     *
     * @param o
     * @return
     */
    public V get(Object o) {
        if (o == null) {
            throw new IllegalStateException("Error: a null identifier was supplied");
        }

        Identifier key = null;
        try {
            key = (Identifier) o;
        } catch (ClassCastException c) {
            throw new NFWException("Error casting object of type \"" + o.getClass().getName() + "\" to an Identifier.\nThis is an implementation error", c);
        }

        Connection c = getConnection();
        V t = null;
        try {
            PreparedStatement stmt = c.prepareStatement(getTable().createSelectStatement());
            stmt.setString(1, key.toString());
            stmt.executeQuery();
            ResultSet rs = stmt.getResultSet();
            // Now we have to pull in all the values.
            if (!rs.next()) {
                rs.close();
                stmt.close();
                return null;   // returning a null fulfills contract for this being a map.
            }

            ColumnMap map = rsToMap(rs);
            rs.close();
            stmt.close();

            t = create();
            populate(map, t);
        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error getting object with identifier \"" + key + "\"", e);
        } finally {
            releaseConnection(c);
        }
        return t;
    }

    /**
     * Take the values in the current row and stash them in a map, keyed by column name.
     *
     * @param rs
     * @return
     * @throws SQLException
     */
    protected ColumnMap rsToMap(ResultSet rs) throws SQLException {
        ColumnMap map = new ColumnMap();
        ResultSetMetaData rsmd = rs.getMetaData();
        int numberOfColumns = rsmd.getColumnCount();
        for (int i = 1; i <= numberOfColumns; i++) {
            String colName = rsmd.getColumnName(i);
            Object obj = null;
            obj = rs.getObject(colName);
            map.put(colName, obj);
        }
        return map;
    }


    public Table getTable() {
        return table;
    }


    Table table;


    public int size() {
        return size(getTable().getFQTablename());
    }

    /**
     * Utility that gets the total number of rows in a given table, given the name.
     *
     * @param tablename
     * @return
     */
    protected int size(String tablename) {
        String query = "SELECT COUNT(*)  from " + tablename;
        Connection c = getConnection();
        int rowCount = 0; // default size

        try {
            PreparedStatement stmt = c.prepareStatement(query);
            stmt.executeQuery();
            ResultSet rs = stmt.getResultSet();
            if (rs.next()) {
                rowCount = rs.getInt(1); // *trick* to get the row count
            }
            rs.close();
            stmt.close();

        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error getting the size.", e);
        } finally {
            releaseConnection(c);
        }
        return rowCount;
    }

    public boolean isEmpty() {
        return size() == 0;
    }

    public boolean containsKey(Object key) {
        Connection c = getConnection();
        boolean rc = false;
        try {
            PreparedStatement stmt = c.prepareStatement(getTable().createSelectStatement());
            stmt.setString(1, key.toString());
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


    public boolean containsValue(Object o) {
        V foo;
        try {
            foo = (V) o;
        } catch (ClassCastException c) {
            // $&*&%% Java generics
            return false;
        }
        return containsKey(foo.getIdentifier());
    }


    public V put(Identifier k, V v) {
        if (v.getIdentifier().equals(k)) {
            save(v);
        }
        return null;
    }

    public V remove(Object key) {
        V oldObject = null;
        try {
            oldObject = get(key);
        } catch (GeneralException x) {
            // fine. Return null. All we care about is whether the next operations work.
        }
        String query = "DELETE FROM " + getTable().getFQTablename() + " WHERE " + getTable().getPrimaryKeyColumnName() + "=?";
        Connection c = getConnection();
        try {
            PreparedStatement stmt = c.prepareStatement(query);
            stmt.setString(1, key.toString());
            stmt.execute();
            stmt.close();
        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error getting identity providers", e);
        } finally {
            releaseConnection(c);
        }
        return oldObject;
    }

    /**
     * A terrifically inefficient way to add these since it loops. If you need this to work better, override and optimize.
     *
     * @param m
     */
    @Override
    public void putAll(Map<? extends Identifier, ? extends V> m) {
        for (Map.Entry e : m.entrySet()) {
            register((V) e.getValue());
        }
    }


    public void clear() {
        String query = "DELETE FROM " + getTable().getFQTablename();
        Connection c = getConnection();
        try {
            PreparedStatement stmt = c.prepareStatement(query);
            stmt.execute();
            stmt.close();
        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error getting identity providers", e);
        } finally {
            releaseConnection(c);
        }
    }


    public Set<Identifier> keySet() {
        HashSet<Identifier> keys = new HashSet<Identifier>();

        String query = "Select " + getTable().getPrimaryKeyColumnName() + " from " + getTable().getFQTablename();
        Connection c = getConnection();
        try {
            PreparedStatement stmt = c.prepareStatement(query);
            stmt.execute();
            ResultSet rs = stmt.getResultSet();
            // Figure out the type of argument. Can't do this in java without annoying reflection
            while (rs.next()) {
                keys.add(new BasicIdentifier(rs.getString(1)));
            }
            rs.close();
            stmt.close();
        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error getting the user ids", e);
        } finally {
            releaseConnection(c);
        }
        return keys;
    }

    /**
     * Again, this is basic functionality for the map interface. Do you really need to get everything in the database?
     * If the database is large, this might fail for various unrelated reasons. If you really need to use a call like
     * this, then you should probably over-ride it and optimize, say with partial retrievals or some such.
     *
     * @return
     */
    public Collection<V> values() {
        Collection<V> allOfThem = new ArrayList<V>();
        Connection c = getConnection();
        try {
            PreparedStatement stmt = c.prepareStatement("select * from " + getTable().getFQTablename());
            stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content per JDBC spec.

            ResultSet rs = stmt.getResultSet();
            while (rs.next()) {
                V newOne = create();
                ColumnMap map = rsToMap(rs);
                populate(map, newOne);
                allOfThem.add(newOne);
            }
            rs.close();
            stmt.close();
        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error: could not get database object", e);
        } finally {
            releaseConnection(c);
        }
        return allOfThem;
    }

    public Set<Entry<Identifier, V>> entrySet() {
        Set<Entry<Identifier, V>> entries = new HashSet<Entry<Identifier, V>>();
        Connection c = getConnection();
        try {
            PreparedStatement stmt = c.prepareStatement("select * from " + getTable().getFQTablename());
            stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content per JDBC spec.

            ResultSet rs = stmt.getResultSet();
            while (rs.next()) {
                V newOne = create();
                ColumnMap map = rsToMap(rs);
                populate(map, newOne);
                entries.add(new SimpleEntryImpl<Identifier, V>(newOne.getIdentifier(), newOne));
            }
            rs.close();
            stmt.close();
        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error: could not get database object", e);
        } finally {
            releaseConnection(c);
        }
        return entries;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[table=" + getTable() + "]";
    }

    /**
     * When invoked this will loop through the columns of the table and add columns as needed with the correct type.
     * NOTE that this should only be run once as a utility at, say, servlet loading time before any data access can
     * occur.
     */
    public void checkColumns() throws SQLException {
        ColumnDescriptors cds = getTable().getColumnDescriptor();
        Connection connection = getConnection();
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * from " + getTable().getFQTablename());
        ResultSetMetaData metaData = rs.getMetaData();
        Hashtable<String, Integer> foundCols = new Hashtable<String, Integer>();
        // have to loop through these and get the column names and types first since we will
        // be altering the table which will change order of the columns potentially and
        // impact all subsequent table structure updates.

        for (int i = 1; i <= metaData.getColumnCount(); i++) {
            foundCols.put(metaData.getColumnName(i).toLowerCase(), metaData.getColumnType(i));
        }

        // Grrrrr.... JDBC should really do this. This grabs the field names from the
        // java.sql.Types class and shoves them in a hashmap for later lookup. Annoying.
        // tres annoying. Needs a final kludge too.
        Map<Integer, String> jdbcMappings = new HashMap<Integer, String>();

        for (Field field : java.sql.Types.class.getFields()) {
            try {
                jdbcMappings.put((Integer) field.get(null), field.getName());
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            }
        }
        // LONGVARCHAR and LONGNVARCHAR are Java SQL types but not SQL-standard.
        // Since every SQL engine uses the more modern type of TEXT instead, we special case this.
        jdbcMappings.put(Types.LONGNVARCHAR, "TEXT");
        jdbcMappings.put(Types.LONGVARCHAR, "TEXT");
        for (ColumnDescriptorEntry cde : cds) {
            if (!foundCols.containsKey(cde.getName().toLowerCase())) {
                // create the column
                String rawStmt = "Alter Table " + getTable().getFQTablename() + " add Column " + cde.getName() + " " + jdbcMappings.get(cde.getType());
                stmt.executeUpdate(rawStmt);
            }
        }
        rs.close();
        stmt.close();
        releaseConnection(connection);
    }
}