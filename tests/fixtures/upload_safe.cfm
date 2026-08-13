<!--- An explicit accept allow-list is the mitigation; nameconflict is not,
      so it must NOT suppress the finding on its own. --->
<cffile action="upload" filefield="doc" destination="#expandPath('/up')#" accept="image/png">
<cffile action="upload" filefield="doc" destination="#expandPath('/up')#" nameconflict="makeunique">  <!--- EXPECT: CF-UPLOAD-001 --->
