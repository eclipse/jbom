package com.contrastsecurity;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.github.packageurl.PackageURL;

import org.cyclonedx.model.Component;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Property;

public class Library extends Component implements Comparable<Library> {

	@JsonIgnore
	public Library parent = null;

	@JsonIgnore
	public boolean isUsed = false;

    @JsonIgnore
    public String jar = null;

    @JsonIgnore
    public String path = null;

    @JsonIgnore
    public int classesUsed = 0;

    public Library() {
    }
    
    public Library( String name ) {
        this.setName( name );
    }

    public void parsePath( String fullpath ) {
        jar = fullpath.substring( fullpath.lastIndexOf("/") + 1 );
        path = fullpath.substring( 0, fullpath.lastIndexOf("/") );

        this.addProperty( "path", path );
        this.addProperty( "archive", jar );
        int sep = fullpath.lastIndexOf( "." );
        String fqn = fullpath.substring( 0, sep );
        this.setName( fqn.substring( fqn.lastIndexOf( "/" ) + 1 ) );
        this.setVersion( fqn.substring( fqn.lastIndexOf( "-" ) + 1 ) );
        try {
            setPurl(new PackageURL("maven", this.getGroup(), this.getName(), this.getVersion(), null, null));
        } catch ( Exception e ) {
            // continue
        }
    }

	public void addProperty( String name, String value ) {
		List<Property> properties = getProperties();
		if ( properties == null ) {
			properties = new ArrayList<Property>();
			setProperties( properties );
		}
		Property p = new Property();
		p.setName( name );
		p.setValue( value );
		properties.add( p );
	}
	
    @Override
    public String toString() {
        List<Hash> hashes = getHashes();
        return "Library"
        + "\n    name     | " + this.getName() + "-" + getVersion()
        + "\n    group    | " + this.getGroup()
        + "\n    artifact | " + this.getName()
        + "\n    version  | " + this.getVersion()
        + "\n    jar      | " + jar
        + "\n    path     | " + path 
        + "\n    md5      | " + hashes.get(0).getValue()
        + "\n    sha1     | " + hashes.get(1).getValue()
        + "\n    maven    | " + "https://search.maven.org/search?q=1:" +hashes.get(1).getValue();
    }

    @Override
    public final boolean equals(Object o) {
        Library that = (Library)o;
        return this.jar.equals(that.jar);
    }

    @Override
    public final int hashCode() {
        return jar.hashCode();
    }

    @Override
    public int compareTo(Library that) {
         return this.jar.compareTo(that.jar);
    }

}