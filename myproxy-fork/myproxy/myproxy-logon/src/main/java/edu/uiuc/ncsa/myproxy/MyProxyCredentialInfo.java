package edu.uiuc.ncsa.myproxy;

import java.util.Date;

public class MyProxyCredentialInfo {

    private String owner;
    private long startTime;
    private long endTime;
    private String name;
    private String description; // optional
    private String renewers;     // optional
    private String retrievers;   // optional

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getRetrievers() {
        return this.retrievers;
    }

    public void setRetrievers(String retrievers) {
        this.retrievers = retrievers;
    }

    public String getRenewers() {
        return this.renewers;
    }

    public void setRenewers(String renewers) {
        this.renewers = renewers;
    }

    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getOwner() {
        return this.owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public long getStartTime() {
        return this.startTime;
    }

    public void setStartTime(long time) {
        this.startTime = time;
    }

    public long getEndTime() {
        return this.endTime;
    }

    public void setEndTime(long time) {
        this.endTime = time;
    }

    public Date getEndTimeAsDate() {
        return new Date(this.endTime);
    }

    public Date getStartTimeAsDate() {
        return new Date(this.startTime);
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        
        buf.append("Owner:" + this.owner + "\n");
        
        if (this.name != null) {
            buf.append(this.name + ":\n");
        } else {
        	buf.append("default :\n");
        }
        
        buf.append("\tStart Time  : " + getStartTimeAsDate() + "\n");
        buf.append("\tEnd Time    : " + getEndTimeAsDate() + "\n");
        
        if (this.description != null) {
            buf.append("\tDescription :"  + this.description + "\n");
        }
        if (this.renewers != null) {
            buf.append("\tRenewers    : " + this.renewers + "\n");
        }
        if (this.retrievers != null) {
            buf.append("\tRetrievers  : " + this.retrievers + "\n");
        }
        return buf.toString();
    }
	
	
}
