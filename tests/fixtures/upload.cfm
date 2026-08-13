<!--- Both attribute orders must be detected. --->
<cffile action="upload" filefield="doc" destination="#expandPath('/up')#">  <!--- EXPECT: CF-UPLOAD-001 --->
<cffile destination="#expandPath('/up')#" filefield="doc" action="upload">  <!--- EXPECT: CF-UPLOAD-001 --->
