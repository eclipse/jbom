package com.contrastsecurity;

import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;

public class Agent {

	public static boolean agentRunning = false;

	public static void premain(String args, Instrumentation inst) {
		transform( args, inst );
	}

	public static void agentmain(String args, Instrumentation inst) {
		transform( args, inst );
	}

	public static void transform(String args, Instrumentation inst) {

		String filename = "sbom.json";
		if ( args != null ) {
			filename = args;
		}

		if ( agentRunning ) {
			Logger.log( "Is jbom already running? Check for multiple -javaagent declarations" );
			return;
		}
		agentRunning = true;

		Logger.log( "==================================" );
		Logger.log( "jbom attached" );
		Libraries libs = new Libraries();
		Class[] classes = inst.getAllLoadedClasses();
		for ( Class clazz : classes ) {
			try {
				if ( !isSkippable( clazz ) ) {
					ProtectionDomain pd = clazz.getProtectionDomain();
					if ( pd != null ) {
						CodeSource cs = pd.getCodeSource();
						if ( cs != null ) {
							URL url = cs.getLocation();
							if ( url != null ) {
								String codesource = url.toString();
								libs.addAllLibraries( clazz, codesource );
							}
						}
					}
				}
			} catch( Exception e ) {
				Logger.log( "Error processing class: " + clazz.getName() );
				e.printStackTrace();
			}
		}

		reportResults( libs, filename );
		Logger.log( "jbom complete" );
		Logger.log( "==================================" );

		agentRunning = false;
	}

	public static boolean isSkippable( Class clazz ) {
		if ( clazz == null || clazz.isArray() || clazz.isPrimitive() || clazz.isInterface() ) {
			return true;
		}

		// skip primordial classloader
		return clazz.getClassLoader() == null;
	}


	public static void reportResults( Libraries libs, String filename ) {
		CycloneDXModel sbom = new CycloneDXModel();
		sbom.setComponents( libs.getLibraries() );
		sbom.setDependencies( libs.getDependencies() );
		sbom.save( filename );
	}
	
}
