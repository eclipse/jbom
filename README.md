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

  ```shell
  ssh hostname
  curl -O https://github.com/Contrast-Security-OSS/jbom/releases/download/v1.0.0/jbom-1.0.0.jar
  java -javaagent:jbom-1.0.0.jar
  cat sbom.json
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
