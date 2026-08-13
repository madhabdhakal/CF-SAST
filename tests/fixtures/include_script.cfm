<cfscript>
    include("views/" & page & ".cfm");         // EXPECT: CF-INCLUDE-002
    include("views/static.cfm");
</cfscript>
