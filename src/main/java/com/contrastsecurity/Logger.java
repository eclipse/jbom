package com.contrastsecurity;

import java.text.SimpleDateFormat;
import java.util.Date;

public class Logger {

	public static SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");  

    public static void log( String msg ) {
        String stamp = formatter.format(new Date());
        String message = stamp + " TRACE --- [jbom] " + msg;
        System.out.println( message );
    }
}