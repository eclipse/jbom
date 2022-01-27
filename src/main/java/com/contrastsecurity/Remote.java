package com.contrastsecurity;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;

public class Remote {

    private String host;
    private String user;
    private String pass;

    public Remote( String host, String user, String pass ) {
        this.host = host;
        this.user = user;
        this.pass = pass;
    }

    public void upload( String remoteDir, File f ) throws JSchException, IOException, SftpException {
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
        } catch( JSchException e ) {
            Logger.log( "Error: " + e.getMessage() );
       } finally {
            if ( channel != null ) {
                channel.disconnect();
            }
            if ( session != null ) {
                session.disconnect();
            }
        }
    }


    public List<String> download( String host, String remoteDir, String localDir ) throws JSchException, IOException {
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
                String localFile = localDir + "/" + en.getFilename();
                if ( en.getFilename().endsWith( ".jar" ) ) {
                    channel.rm( remoteFile );
                }

                channel.get( remoteFile, localFile );
                channel.rm( remoteFile );
                files.add( localFile );
            }
        } catch( JSchException e ) {
            Logger.log( "Error: " + e.getMessage() );
        } catch (SftpException e) {
            Logger.log( "Error: " + e.getMessage() );
        } finally {
            if ( channel != null ) {
                channel.disconnect();
            }
            if ( session != null ) {
                session.disconnect();
            }
        }
        return files;
    }

    public void rmdir( String dir ) throws JSchException, IOException {
        exec( "rm -rf " + dir );
    }


    public String exec(String command) throws JSchException, IOException {
        Logger.debug( "Remote exec: " + command );
        Session session = null;
        ChannelExec channel = null;
        session = getSession();
        channel = (ChannelExec)session.openChannel("exec");
        ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
        ByteArrayOutputStream errorBuffer = new ByteArrayOutputStream();
        
        try {
            channel.setCommand( command );
            channel.connect();

            InputStream in = channel.getInputStream();
            InputStream err = channel.getExtInputStream();
            
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
        } catch( JSchException e ) {
            Logger.log( "Error: " + e.getMessage() );
        } finally {
            if ( channel != null ) {
                channel.disconnect();
            }
            if ( session != null ) {
                session.disconnect();
            }
        }
        return outputBuffer.toString("UTF-8");
   }

    public ChannelSftp getSftpChannel( Session session ) throws JSchException {
        Channel channel = session.openChannel("sftp");
        channel.connect();
        ChannelSftp sftpChannel = (ChannelSftp)channel;
        return sftpChannel;
    }

    public Session getSession() throws JSchException {
        Session session = new JSch().getSession(user, host, 22);
        session.setPassword(pass);
        session.setConfig("PreferredAuthentications", "publickey,keyboard-interactive,password");
        session.setConfig("StrictHostKeyChecking", "no"); // disable check for RSA key
        session.connect();
        return session;
    }

}
