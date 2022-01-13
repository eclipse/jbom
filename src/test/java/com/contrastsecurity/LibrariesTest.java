package com.contrastsecurity;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.Test;


public class LibrariesTest {

    @Test
    public void testFile() throws Exception {
        String jar = "src/test/resources/spring-petclinic-1.5.1.jar";
        Jbom jbom = new Jbom();
        Libraries libs = jbom.doFile( jar, "target/test" );
        assertTrue( "Incorrect number of libraries found. " + libs.getLibraries().size() + " instead of 135", libs.getLibraries().size() == 135 );
    }


    @Test
    public void testDir() throws Exception {
        String dir = "src/test/resources";
        Jbom jbom = new Jbom();
        Libraries libs = jbom.doDirectory( dir, "target/test" );
        assertTrue( "Incorrect number of libraries found. " + libs.getLibraries().size() + " instead of 138", libs.getLibraries().size() == 138 );
    }

}