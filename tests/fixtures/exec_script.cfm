<cfscript>
    cfexecute(name = "/bin/sh", arguments = "-c ls", timeout = 5);  // EXPECT: CF-EXEC-002
</cfscript>
