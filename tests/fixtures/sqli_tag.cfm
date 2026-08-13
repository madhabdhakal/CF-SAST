<!--- Raw interpolation directly in a cfquery body. --->
<cfquery name="getUser" datasource="ds">
    SELECT * FROM users WHERE id = #url.id#   <!--- EXPECT: CF-SQLI-001 --->
</cfquery>
