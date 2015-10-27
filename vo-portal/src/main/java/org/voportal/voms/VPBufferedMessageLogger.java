package org.voportal.voms;

import java.io.PrintStream;

import org.italiangrid.voms.clients.util.MessageLogger;

public class VPBufferedMessageLogger extends MessageLogger {

	  public VPBufferedMessageLogger(PrintStream out,PrintStream err) {
		    super(out, err, DEFAULT, MessageLevel.INFO);
	  }
	
}
