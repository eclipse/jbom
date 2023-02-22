package com.contrastsecurity;

import java.io.File;
import java.io.IOException;
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
		jbom.setName("jbom - https://projects.eclipse.org/projects/technology.jbom");
		jbom.setVendor("Contrast Security - https://contrastsecurity.com");
		final Properties properties = new Properties();
		try {
			properties.load(CycloneDXModel.class.getClassLoader().getResourceAsStream("jdom.properties"));
			jbom.setVersion(properties.getProperty("version"));
		} catch (IOException e1) {
			e1.printStackTrace();
			Logger.log("ERROR: can't find version property in jdom.properties file");
			jbom.setVersion("unknown");
		}
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
