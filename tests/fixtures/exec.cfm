<!--- Kept free of #url.x# interpolation so this fixture tests only CF-EXEC-001. --->
<cfexecute name="/bin/sh" arguments="-c ls" timeout="5"></cfexecute>  <!--- EXPECT: CF-EXEC-001 --->
<cfset r = createObject("java", "java.lang.Runtime").getRuntime().exec(cmd)>  <!--- EXPECT: CF-EXEC-001 --->
