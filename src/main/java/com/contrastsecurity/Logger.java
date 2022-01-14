package com.contrastsecurity;

import java.text.SimpleDateFormat;
import java.util.Date;

public class Logger {

	public static SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");  
    private static boolean debug = false;

    public static void log( String msg ) {
        String stamp = formatter.format(new Date());
        String message = stamp + " TRACE --- [jbom] " + msg;
        System.out.println( message );
    }

    public static void debug( String msg ) {
        if ( debug ) {
            String stamp = formatter.format(new Date());
            String message = stamp + " DEBUG --- [jbom] " + msg;
            System.out.println( message );
        }
    }

    public static void setDebug(boolean debug) {
        Logger.debug = debug;
    }
}