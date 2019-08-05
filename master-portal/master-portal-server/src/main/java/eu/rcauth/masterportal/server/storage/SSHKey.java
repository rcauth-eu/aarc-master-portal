package eu.rcauth.masterportal.server.storage;

import java.io.Serializable;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;

/**
 * <p>Created by Mischa Sall&eacute;<br>
 * SSHKey objects describe individual SSH public keys: identified by the unique
 * combination label, username, they further contain a single public key and an
 * optional description.
 */
public class SSHKey extends IdentifiableImpl {

    /**
     * Since SSHKey implements {@link Serializable} via its superclass it's
     * strongly recommended to define a serialVersionUID.
     * See {@link Serializable} for the rationale.
     */
    protected static final long serialVersionUID = 0xC1EBC4C3;

    protected String label;
    protected String userName;
    protected String pubKey;
    protected String description;

    /**
     * constructs an SSHKey from given identifier, note that this does not work
     * properly as we don't fully implement SSHKeyIdentifier.
     */
    public SSHKey(SSHKeyIdentifier identifier) {
        super(identifier);
    }

    /**
     * constructs a new SSHKey for given userName and label. Public key and
     * description are set to null.
     */
    public SSHKey(String userName, String label) {
        super(new SSHKeyIdentifier(userName, label));
        this.userName=userName;
        this.label=label;
        this.pubKey=null;
        this.description=null;
    }

    /**
     * constructs a new SSHKey for given userName, label, public key and
     * description.
     */
    public SSHKey(String userName, String label, String pubKey, String description) {
        super(new SSHKeyIdentifier(userName, label));
        this.userName=userName;
        this.label=label;
        this.pubKey=pubKey;
        this.description=description;
    }

    /* GETTERS AND SETTERS */

    /** set label */
    public void setLabel(String label) {
        this.label = label;
    }

    /** @return label */
    public String getLabel() {
        return label;
    }

    /** set username */
    public void setUserName(String userName) {
        this.userName = userName;
    }

    /** @return username */
    public String getUserName() {
        return userName;
    }

    /** set public key */
    public void setPubKey(String pubKey) {
        this.pubKey = pubKey;
    }

    /** @return public key */
    public String getPubKey() {
        return pubKey;
    }

    /** set description */
    public void setDescription(String description) {
        this.description = description;
    }

    /** @return description */
    public String getDescription() {
        return description;
    }

    /** set identifier */
    @Override
    public void setIdentifier(Identifier identifier) {
        super.setIdentifier(identifier);
    }

    /**
     * Checks whether two SSHKey objects are equal. Note that keys are
     * uniquely identified using their username/label pair. Keys are considered
     * equal when both the username and label matches. In case both pubKeys are
     * set, they also need to match.
     * @return boolean indicating whether the keys match.
     */
    @Override
    public boolean equals(Object obj) {
        if (super.equals(obj) && obj instanceof SSHKey) {
            SSHKey rec = (SSHKey) obj;
            // Note: we identify a key using the pair username/label.
            // Also note that pubKey might still be null.
            if (pubKey!=null && rec.getPubKey()!=null) {
                return (checkEquals(userName, rec.getUserName()) &&
                        checkEquals(label, rec.getLabel()) &&
                        checkEquals(pubKey, rec.getPubKey()));
            } else {
                return (checkEquals(userName, rec.getUserName()) &&
                        checkEquals(label, rec.getLabel()));
            }
        }
        return false;
    }

    /** @return printable representation of the key fields */
    @Override
    public String toString() {
    return "SSHKey: \n" +
           "	label:      " + label + "\n" +
           "	username:   " + userName + "\n" +
           "	publickey:  " + pubKey + "\n"+
           "	description:" + description + "\n";

    }

}
