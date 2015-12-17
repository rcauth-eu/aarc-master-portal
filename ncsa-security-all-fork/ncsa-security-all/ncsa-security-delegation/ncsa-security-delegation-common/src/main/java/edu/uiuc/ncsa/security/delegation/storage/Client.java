package edu.uiuc.ncsa.security.delegation.storage;


import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;

import java.util.Date;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;

/**
 * Models a client.
 * <p>Created by Jeff Gaynor<br>
 * on Mar 15, 2011 at  5:09:20 PM
 */


public class Client extends IdentifiableImpl {
    public boolean isProxyLimited() {
        return proxyLimited;
    }

    public void setProxyLimited(boolean proxyLimited) {
        this.proxyLimited = proxyLimited;
    }

    boolean proxyLimited = false;

    public Client(Identifier identifier) {
        super(identifier);
    }

    public String getHomeUri() {
        return homeUri;
    }

    public void setHomeUri(String homeUri) {
        this.homeUri = homeUri;
    }

    String homeUri;


    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    String secret;

    String name;
    Date creationTS;
    String errorUri;
    String email;


    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getErrorUri() {
        return errorUri;
    }

    public void setErrorUri(String errorUri) {
        this.errorUri = errorUri;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Date getCreationTS() {

        return creationTS;
    }

    public void setCreationTS(Date creationTS) {
        this.creationTS = creationTS;
    }


    @Override
    public boolean equals(Object obj) {
        if(!super.equals(obj)) return false;
        Client c = (Client) obj;
        if (!checkEquals(getSecret(), c.getSecret())) return false;
        if (!checkEquals(getHomeUri(), c.getHomeUri())) return false;
        if (!checkEquals(getName(), c.getName())) return false;
        if (!checkEquals(getErrorUri(), c.getErrorUri())) return false;
        if (!checkEquals(getEmail(), c.getEmail())) return false;
        if (isProxyLimited() != c.isProxyLimited()) return false;
        if (!DateUtils.equals(getCreationTS(), c.getCreationTS())) return false;
        return true;
    }


    @Override
    public String toString() {
        return getClass().getSimpleName() + "[name=\"" + getName() +
                "\", id=\"" + getIdentifierString() +
                "\", homeUri=\"" + getHomeUri() +
                "\", errorUri=\"" + getErrorUri() +
                "\", email=\"" + getEmail() +
                "\", secret=" + (getSecret()==null?"(none)":getSecret().substring(0,25)) +
                "\", proxy limited=" + isProxyLimited() +
                "]";
    }

}
