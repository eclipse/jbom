# jbom

<p align="center"><b>
<br>
<br>
jbom generates a Software Bill of Materials (SBOM) for apps on a running JVM
<br>
<br>
</b></p>

Advantages:
* produces standard CycloneDX SBOM in JSON format
* fast and accurate
* finds all libraries, including platform, appserver, plug-in, and dynamic sources.
* doesn't report test or other libraries not present at runtime
* handles nested jar, war, ear, and zip files
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


## Attaching to a running JVM with jbom...
 First list eligible JVM processes running on the server.
  ```shell
  ssh hostname
  curl -O https://github.com/Contrast-Security-OSS/jbom/releases/download/v1.0.0/jbom-1.0.0.jar
  java -jar jbom-1.0.0.jar 
  ...
  List of eligible JVM PIDs (must be running as same user):
  1234 	com.some.App
  4321 	com.another.App
  ```
Then run
  ```shell
  java -jar jbom-1.0.0.jar -p 1234 -o /tmp/sbom.json
  ```

Which will attach jbom to the process 1234, inject the sbom generation code into process 1234 and execute it.
A few things to note :
* As the code is executed on the target JVM, if you do not specify an output file, it will write it to a file named "sbom.json" under the target JVMs current working directory. Not the directory you are running the jbom.jar from.
* The execution of the sbom generation happens asynchronously of the exit of the jbom.jar. So the jbom.jar may exit before the sbom.json is written to disk. You may have to wait 30 seconds or so after exit of the jbom.jar for the sbom.json file to be generated.d


## Attaching jbom as a Java Agent...
  ```shell
  ssh hostname
  curl -O https://github.com/Contrast-Security-OSS/jbom/releases/download/v1.0.0/jbom-1.0.0.jar
  java -jar jbom-1.0.0.jar 
  java -javaagent:jbom-1.0.0.jar=/tmp/sbom.json -jar yourapplication.jar
  ```
When running as a java agent, only one argument is possible which is to specify the location of the sbom.json as shown in the above example. If not set the sbom.json will be outputted to the current working directory.





## Scanning a build artifact...
It is possible to scan a build artifact ( ear/war/jar )
  ```shell
  ssh hostname
  curl -O https://github.com/Contrast-Security-OSS/jbom/releases/download/v1.0.0/jbom-1.0.0.jar
  java -jar jbom-1.0.0.jar -f nameOfYourBuildArtifact.jar -o /tmp/sbom.json
  cat /tmp/sbom.json
  ```


## Building and Contributing

We welcome pull requests and issues. Thanks!

   ```shell
   git clone 
   mvn clean install
   java -jar target/jbom-x.x.x.jar
   ``` 


## License

This software is licensed under the Apache 2 license

Copyright 2021 Contrast Security - https://contrastsecurity.com

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this project except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
