package com.contrastsecurity;

import java.io.File;

import net.bytebuddy.agent.ByteBuddyAgent;

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
