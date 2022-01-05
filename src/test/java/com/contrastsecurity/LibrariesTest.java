package com.contrastsecurity;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.Test;


public class LibrariesTest {

    @Test
    public void runTest() throws Exception {
        String jar = "spring-petclinic-1.5.1.jar";
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource(jar).getFile());
        Libraries.runScan( file, "target/test/petclinic-1.5.1.sbom" );
        System.out.println( "Libraries found in "+file+": " + Libraries.getLibraries().size() );
        assertTrue( "Correct nmber of libraries found", Libraries.getLibraries().size() == 135 );
    }

}