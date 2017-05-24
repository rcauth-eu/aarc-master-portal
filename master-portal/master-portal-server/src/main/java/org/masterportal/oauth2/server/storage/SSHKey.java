package org.masterportal.oauth2.server.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;

import java.util.List;


public class SSHKey extends IdentifiableImpl {

//    private static final long serialVersionUID = -7707448168067694856L;

    protected String label;
    protected String userName;
    protected String pubKey;
    protected String description;
    
    
    public SSHKey(SSHKeyIdentifier identifier) {
	super(identifier);
    }

    public SSHKey(String userName, String label) {
	super(new SSHKeyIdentifier(userName, label));
	this.userName=userName;
	this.label=label;
	this.pubKey=null;
	this.description=null;
    }
    
    public SSHKey(String userName, String label, String pubKey, String description) {
	super(new SSHKeyIdentifier(userName, label));
	this.userName=userName;
	this.label=label;
	this.pubKey=pubKey;
	this.description=description;
    }
    
    /* GETTERS AND SETTERS */
    
    public void setLabel(String label) {
	this.label = label;
    }
    
    public String getLabel() {
	return label;
    }
    
    public void setUserName(String userName) {
	this.userName = userName;
    }
    
    public String getUserName() {
	return userName;
    }
    
    public void setPubKey(String pubKey) {
	this.pubKey = pubKey;
    }
    
    public String getPubKey() {
	return pubKey;
    }
    
    public void setDescription(String description) {
	this.description = description;
    }
    
    public String getDescription() {
	return description;
    }
    
    
    @Override
    public void setIdentifier(Identifier identifier) {
	super.setIdentifier(identifier);
    }
	    
    @Override
    public boolean equals(Object obj) {
	if (super.equals(obj) && obj instanceof SSHKey) {
	    SSHKey rec = (SSHKey) obj;
	    if (checkEquals(getUserName(), rec.getUserName()) &&
		checkEquals(getPubKey(), rec.getPubKey()) )	{
		return true;
	    }
	}
	return false;
    }
    
    @Override
    public String toString() {
	return "SSHKey: \n" + 
	   "	username:   " + userName + "\n" +
	   "	publickey:  " + pubKey + "\n"+
	   "	description:" + description + "\n";

    }
    
}
