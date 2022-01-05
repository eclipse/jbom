package com.contrastsecurity;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.List;

import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;

import net.bytebuddy.agent.ByteBuddyAgent;
import picocli.CommandLine;

public class App implements Runnable {

    @CommandLine.Option(names = { "-p", "--pid" }, description = "JVM PID to attach to")
    private int pid = -1;

    @CommandLine.Option(names = { "-f", "--file" }, description = "File to be scanned")
    private File file;

    @CommandLine.Option(names = { "-o", "--output" }, defaultValue = "sbom.json", description = "Output path")
    private String outputPath;


    public static void main(String[] args){
        new CommandLine(new App()).execute(args);
    }

    private static void showHelp(){
        System.out.println();
        System.out.println("List of eligible JVM PIDs (must be running as same user):");
        try{
            ensureToolsJar();
            listProcesses();
        }catch(NoClassDefFoundError err){
            System.err.println("Error. Try using 'jps' or 'jcmd' to list Java processes.");
        }
        System.out.println();
        System.out.println("To attach jbom a JVM use:");
        System.out.println("$ java -jar jbom-1.0.0.jar [pid]");
        // FIXME: add ALL option
        System.out.println();
    }

    public static void listProcesses(){
        List<VirtualMachineDescriptor> vms = VirtualMachine.list();
        vms.stream()
            .filter(vm -> !vm.displayName().contains("jbom")) //No need to patch ourselves
            .forEach(vm -> {
            System.out.println(vm.id() + " \t" + vm.displayName());
        });
    }

    public static void ensureToolsJar() {
		if (App.class.getResource("/sun.jvmstat.monitor.MonitoredVm".replace('.', '/') + ".class") == null) {
            try {
                String javaHome = System.getProperty("java.home");
                String toolsJarURL = "file:" + javaHome + "/../lib/tools.jar";

                // Make addURL accessible
                Method method = URLClassLoader.class.getDeclaredMethod("addURL", URL.class);
                method.setAccessible(true);

                URLClassLoader sysloader = (URLClassLoader)ClassLoader.getSystemClassLoader();
                if (sysloader.getResourceAsStream("/com/sun/tools/attach/VirtualMachine.class") == null) {
                    method.invoke(sysloader, (Object) new URL(toolsJarURL));
                    Thread.currentThread().getContextClassLoader().loadClass("com.sun.tools.attach.VirtualMachine");
                    Thread.currentThread().getContextClassLoader().loadClass("com.sun.tools.attach.AttachNotSupportedException");
                }

            } catch (Exception e) {
                System.out.println("Java home points to " + System.getProperty("java.home") + " make sure it is not a JRE path");
                e.printStackTrace();
            }
		}
    }

    @Override
    public void run() {
        Logger.log( "" );
        Logger.log( "                           _ __" );
        Logger.log( "                          (_) /_  ____  ____ ___" );
        Logger.log( "                         / / __ \\/ __ \\/ __ `__ \\" );
        Logger.log( "                        / / /_/ / /_/ / / / / / /" );
        Logger.log( "                     __/ /_.___/\\____/_/ /_/ /_/" );
        Logger.log( "                    /___/" );
        Logger.log( "          by Contrast Security - https://contrastsecurity.com" );
        Logger.log( "" );
        Logger.log( " jbom generates a Software Bill of Materials (SBOM) for apps on a running JVM" );
        Logger.log( "              https://github.com/Contrast-Security-OSS/jbom" );
        Logger.log( "" );

        if (pid != -1) {
            try{
                String filename = App.class.getProtectionDomain()
                        .getCodeSource()
                        .getLocation()
                        .toURI()
                        .getPath();
                File agentFile = new File(filename);
                ByteBuddyAgent.attach(agentFile.getAbsoluteFile(), Integer.toString(pid), outputPath);
                System.out.println("Attached to target jvm and loaded agent successfully");
                System.out.println();
            }catch(Exception e){
                e.printStackTrace();
            }
        } else if ( file != null ) {
            try{
                Libraries.runScan(file,outputPath);
            }catch(Exception e){
                e.printStackTrace();
            }
        } else {
            showHelp();
        }

    }
}
