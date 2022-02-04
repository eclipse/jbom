package com.contrastsecurity;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

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
    public boolean equals(Object o) {
        if(o instanceof Library) {
            Library that = (Library) o;
            return (this.getName() + this.getVersion() + this.getGroup()).equals(that.getName() + that.getVersion() + that.getGroup());
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.getName()+this.getVersion()+this.getGroup());
    }

    @Override
    public int compareTo(Library that) {
         return this.jar.compareTo(that.jar);
    }

}