package com.contrastsecurity;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

public class Remote {

    private String host;
    private String user;
    private String pass;

    public Remote( String host, String user, String pass ) {
        this.host = host;
        this.user = user;
        this.pass = pass;
    }

    public void upload( String remoteDir, File f ) {
        Logger.debug( "Remote upload: " + f.getAbsolutePath() + " to " + remoteDir );

        Session session = null;
        ChannelSftp channel = null;
        try {
            session = getSession();
            channel = getSftpChannel( session );

            rmdir( remoteDir );
            channel.mkdir( remoteDir );
            channel.cd( remoteDir );
            FileInputStream fis = new FileInputStream(f);
            channel.put(fis, f.getName() );
            fis.close();
        } catch( Exception e ) {
            Logger.log( "Error uploading " + f.getName() + " to " + remoteDir );
            e.printStackTrace();
        } finally {
            channel.disconnect();
            session.disconnect();
        }
    }


    public List<String> download( String host, String remoteDir, String localDir ) {
        Logger.debug( "Remote download: " + remoteDir + " to " + localDir );

        Session session = null;
        ChannelSftp channel = null;
        List<String> files = new ArrayList<String>();
        try {
            session = getSession();
            channel = getSftpChannel( session );
            
            Vector<ChannelSftp.LsEntry> entries = channel.ls(remoteDir);
            for (ChannelSftp.LsEntry en : entries) {
                if ( en.getAttrs().isDir() || !en.getFilename().endsWith(".json") ) {
                    continue;
                }

                String remoteFile = remoteDir + "/" + en.getFilename();
                String localFile = localDir + "/" + host + "-" + en.getFilename();
                if ( en.getFilename().endsWith( ".jar" ) ) {
                    channel.rm( remoteFile );
                }

                channel.get( remoteFile, localFile );
                channel.rm( remoteFile );
                files.add( localFile );
            }
        } catch( Exception e ) {
            Logger.log( "Error during download" );
            e.printStackTrace();
        } finally {
            channel.disconnect();
            session.disconnect();
        }
        return files;
    }

    public void rmdir( String dir ) {
        exec( "rm -rf " + dir );
    }


    public void exec(String command) {
        Logger.debug( "Remote exec: " + command );
        Session session = null;
        ChannelExec channel = null;
        try {
            session = getSession();
            channel = (ChannelExec)session.openChannel("exec");

            channel.setCommand( command );
            channel.connect();

            InputStream in = channel.getInputStream();
            InputStream err = channel.getExtInputStream();
            
            ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
            ByteArrayOutputStream errorBuffer = new ByteArrayOutputStream();
            
            byte[] tmp = new byte[1024];
            while (true) {
                while (in.available() > 0) {
                    int i = in.read(tmp, 0, 1024);
                    if (i < 0) break;
                    outputBuffer.write(tmp, 0, i);
                }
                while (err.available() > 0) {
                    int i = err.read(tmp, 0, 1024);
                    if (i < 0) break;
                    errorBuffer.write(tmp, 0, i);
                }
                if (channel.isClosed()) {
                    if ((in.available() > 0) || (err.available() > 0)) continue; 
                    break;
                }
                try { 
                    Thread.sleep(1000);
                } catch (Exception ee) {
                }
            }
            
            Logger.debug( "=======================================");
            Logger.debug("exit  : " + channel.getExitStatus());
            Logger.debug("output: " + outputBuffer.toString("UTF-8"));
            Logger.debug("error : " + errorBuffer.toString("UTF-8"));
            Logger.debug( "=======================================");
        } catch( Exception e ) {
            Logger.log( "Error executing " + command );
            Logger.log( "  " + e.getMessage() );
        } finally {
            channel.disconnect();
            session.disconnect();
        }
   }

    public ChannelSftp getSftpChannel( Session session ) throws Exception {
        Channel channel = session.openChannel("sftp");
        channel.connect();
        ChannelSftp sftpChannel = (ChannelSftp)channel;
        return sftpChannel;
    }

    public Session getSession() throws Exception {
        Session session = new JSch().getSession(user, host, 22);
        session.setPassword(pass);
        session.setConfig("PreferredAuthentications", "publickey,keyboard-interactive,password");
        session.setConfig("StrictHostKeyChecking", "no"); // disable check for RSA key
        session.connect();
        return session;
    }

}
