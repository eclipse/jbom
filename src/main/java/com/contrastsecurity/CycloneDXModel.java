package com.contrastsecurity;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import org.apache.commons.io.FileUtils;
import org.cyclonedx.BomGeneratorFactory;
import org.cyclonedx.CycloneDxSchema;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.OrganizationalEntity;
import org.cyclonedx.model.Tool;

public class CycloneDXModel extends Bom {

	public CycloneDXModel() {
		setVersion(1);
		setMetadata( makeMetadata() );
		setSerialNumber( UUID.randomUUID().toString() );
	}

	public static Metadata makeMetadata() {
		Metadata meta = new Metadata();
		meta.setTimestamp( new Date() );
		Tool jbom = new Tool();
		jbom.setName("jbom");
		jbom.setVendor("Eclipse Foundation - https://projects.eclipse.org/projects/technology.jbom");
		jbom.setVersion(getJbomVersion());
		meta.setTools( new ArrayList<>(Arrays.asList(jbom)) );

		String description = "Java";
		String hostname = "unknown";
		try {
			hostname =
			InetAddress.getLocalHost().getHostAddress() + " (" + 
			InetAddress.getLocalHost().getHostName() + ")";
		} catch( Exception e ) {
			// continue
		}

		Library appNode = new Library( hostname );
		appNode.setType( Component.Type.APPLICATION );
		appNode.setDescription( description );
		meta.setComponent( appNode );

		OrganizationalEntity manufacturer = new OrganizationalEntity();
		manufacturer.setName( "Unknown" );
		meta.setManufacture(manufacturer);

		return meta;
	}
	
	private static String getJbomVersion() {
        String version = "unknown";
		final Properties properties = new Properties();
		try {
			InputStream is = CycloneDXModel.class.getResourceAsStream("/jdom.properties");
		    properties.load( is );
            version = properties.getProperty("version");
		} catch (Exception e) {
		    // continue	
		}
		return version;
	}

	public void save( String filename ) {
		try {
			List<Component> components = getComponents();
			int size = 0;
			if ( components != null ) {
				size = components.size();
			}
			Logger.log( "Saving SBOM with " + size + " components to " + filename );
			BomJsonGenerator bomGenerator = BomGeneratorFactory.createJson(CycloneDxSchema.VERSION_LATEST, this);
			String bomString = bomGenerator.toJsonString();			
			FileUtils.write(new File(filename), bomString, Charset.forName("UTF-8"), false);		
		} catch( Exception e ) {
			Logger.log( "Couldn't save SBOM to " + filename );
			e.printStackTrace();
		}
	}

}
