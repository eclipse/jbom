package com.contrastsecurity;

import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.agent.builder.AgentBuilder.RedefinitionStrategy;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType.Builder;
import net.bytebuddy.utility.JavaModule;

import static net.bytebuddy.matcher.ElementMatchers.*;

public class Jbom {

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
			Logger.log( "Already running? Check for multiple -javaagent declarations" );
			return;
		}
		agentRunning = true;

		Logger.log( "                         _ __" );
		Logger.log( "                        (_) /_  ____  ____ ___" );
		Logger.log( "                       / / __ \\/ __ \\/ __ `__ \\" );
		Logger.log( "                      / / /_/ / /_/ / / / / / /" );
		Logger.log( "                   __/ /_.___/\\____/_/ /_/ /_/" );
		Logger.log( "                  /___/" );
		Logger.log( "        by Contrast Security - https://contrastsecurity.com" );
		Logger.log( "" );
		Logger.log( "jbom generates a Software Bill of Materials (SBOM) from a running JVM" );
		Logger.log( "           https://github.com/Contrast-Security-OSS/jbom" );
		Logger.log( "" );

		new AgentBuilder.Default()
		.with(RedefinitionStrategy.RETRANSFORMATION)

		// .with(AgentBuilder.Listener.StreamWriting.toSystemError().withTransformationsOnly())
		// .with(AgentBuilder.Listener.StreamWriting.toSystemError().withErrorsOnly())

		.type(new AgentBuilder.RawMatcher() {
			@Override
			public boolean matches(TypeDescription typeDescription, ClassLoader classLoader, JavaModule module, Class<?> classBeingRedefined, ProtectionDomain protectionDomain) {
				Libraries.addAllLibraries( protectionDomain.getCodeSource().getLocation().toString() );
				return false;
			}
		})
		.transform(new AgentBuilder.Transformer() {
			@Override
			public Builder<?> transform(Builder<?> builder, TypeDescription typeDescription, ClassLoader classLoader, JavaModule module) {
				return null;
			}
		})
		
		.installOn(inst);

		reportResults( filename );
	}


	public static void createSBOM() {

	}

	public static void reportResults( String filename ) {
		Runnable thread = new Runnable() {
			public void run() {
				Logger.log( "Waiting 30 seconds for classloading..." );
				try {
					Thread.sleep( 30 * 1000 );
				} catch( Exception e ) {
				}
				Logger.log("Writing SBOM with " + Libraries.getLibraries().size() + " libraries");
				CycloneDXModel sbom = new CycloneDXModel();
				sbom.setComponents( Libraries.getLibraries() );	
				sbom.save( filename );	
			}        
		};
		new Thread(thread).start();
	}
	
}
