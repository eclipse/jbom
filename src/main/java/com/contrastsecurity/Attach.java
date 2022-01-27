package com.contrastsecurity;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Method;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;

import org.apache.commons.io.LineIterator;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.stream.LogOutputStream;

import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.ByteBuddyAgent.ProcessProvider;
import picocli.CommandLine;
import picocli.CommandLine.Command;

public class Attach {
        
    public static void main(String[] args) throws Exception {
        new Attach().run( args[0] );
    }

    public void run( String pid ) throws Exception {
        File agent = getAgentFile();
        ByteBuddyAgent.attach( agent, pid, "options" );
    }

    
    private File getAgentFile() throws Exception {
        String filename = Attach.class
        .getProtectionDomain()
        .getCodeSource()
        .getLocation()
        .toURI()
        .getPath();
        File agentFile = new File(filename);
        return agentFile;
    }

}
