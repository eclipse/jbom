# jbom

<p align="center"><b>
<br>
<br>
jbom generates Runtime and Static SBOMs for local and remote Java apps
<br>
<br>
</b></p>

Every project should create a Software Bill of Materials (SBOM) and make it available, so that people know what ingredients are inside.  You've got a few options for generating SBOMs:

GOOD) __Static SBOM (source)__ - This works fine, but you'll miss runtime libraries from appservers and runtime platforms. You'll also include libraries that don't matter like test frameworks.  You'll also have no idea which libraries are actually active in the running application.
BETTER) __Static SBOM (binary)__ - You'll still miss parts, because code can be located in a variety of different places. And you'll also probably include libraries that don't matter but happen to be on the filesystem.
BEST) __Runtime SBOM__ - This is what 'jbom' is all about. Runtime SBOM is the most accurate approach as it captures the exact libraries used by the application, even if they are in the platform, appserver, plugins, or anywhere else. This approach can also include details of services invoked and which libraries are active.

jbom advantages:
* very fast, complete, and accurate
* produces standard CycloneDX SBOM in JSON format
* works on both running apps/APIs and binaries
* finds all libraries, including platform, appserver, plug-in, and dynamic sources.
* doesn't report test or other libraries not present at runtime
* handles nested jar, war, ear, and zip files (including Spring)
* handles jars using common shaded and relocation techniques
* no source code required

![jbom-screenshot](https://github.com/Contrast-Security-OSS/jbom/blob/main/resources/jbom-screenshot.png?raw=true)


## Why should you use instrumentation-based security tools

Instrumentation has been around for decades, is widely used in performance tools, debugging and profiling, and app frameworks. Many security tools scan from the 'outside-in' and don't have the full context of the running application.  This leads to false-positives, false-negatives, and long scan times.

Instrumentation allows us to do security analysis from within the running application - by watching the code run.  Directly measuring security from within the running code has speed, coverage, and accuracy benefits.  Using instrumentation to analyze for vulnerabilities is often called IAST (Interactive Application Security Testing). Using instrumentation to identify attacks and prevent exploit is often called RASP (Runtime Application Self-Protection).

Remember, you may be getting false results from other approaches. Scanning file systems, code repos, or containers could easily fail to detect libraries accurately.

* library could be buried in a fat jar, war, or ear
* library could be shaded in another jar
* library could be included in the appserver, not the code repo
* library could be part of dynamically loaded code or plugin
* library could be many different versions with different classloaders in a single app
* library could be masked by use of slf4j or other layers
* library could be renamed, recompiled, or otherwise changed



## Examples

Download the [latest release](https://github.com/Contrast-Security-OSS/jbom/releases/latest).

Generate an SBOM for all Java processes running locally
  ```shell
  java -jar:jbom-1.2.jar
  ```
  
Generate an SBOM for all Java processes on a remote host
  ```shell
  java -jar:jbom-1.2.jar -h 192.168.1.42
  ```
  
Generate an SBOM for a local archive file (.jar, .war, .ear, .zip)
  ```shell
  java -jar:jbom-1.2.jar -f mywebapp.jar
  ```

Generate an SBOM for all archive files in a directory
  ```shell
  java -jar:jbom-1.2.jar -f mywebapp
  ```
  
Generate an SBOM for all archive files in a remote directory
  ```shell
  java -jar:jbom-1.2.jar -h 192.168.1.42 -d /var/tomcat/webapps
  ```



## Usage

```
Usage: java -jar sbom-1.2.jar [-D] [-d=<dir>] [-f=<file>] [-h=<host>] [-o=<outputDir>]
                    [-p=<pid>] [-P=<pass>] [-r=<remoteDir>] [-t=<tag>]
                    [-U=<user>] [-x=<exclude>]
  -d, --dir=<dir>              Directory to be scanned
  -D, --debug                  Enable debug output
  -f, --file=<file>            File to be scanned
  -h, --host=<host>            Hostname or IP address to connect to
  -o, --outputDir=<outputDir>  Output directory
  -p, --pid=<pid>              Java process pid to attach to or 'all'
  -P, --password=<pass>        Password for user
  -r, --remote=<remoteDir>     Remote directory to use (default: /tmp/jbom)
  -t, --tag=<tag>              Tag to use in output filenames
  -U, --user=<user>            Username of user to connect as
  -x, --exclude=<exclude>      Java process pid to exclude
   ``` 



## Building and Contributing

We welcome pull requests and issues. Thanks!

   ```shell
   git clone 
   mvn clean install
   java -jar target/jbom-1.2.jar
   ``` 


## License

This software is licensed under the Apache 2 license

Copyright 2021 [Contrast Security](https://contrastsecurity.com) - https://contrastsecurity.com

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) (the "License"); you may not use this project except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
