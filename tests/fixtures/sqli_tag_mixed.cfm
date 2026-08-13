<!--- Partially parameterized query: the second clause is still injectable.
      This is the most common real-world CFML injection shape. --->
<cfquery name="findUser" datasource="ds">
    SELECT * FROM users
    WHERE id = <cfqueryparam value="#url.id#" cfsqltype="cf_sql_integer">
      AND name = '#url.name#'                 <!--- EXPECT: CF-SQLI-001 --->
      AND org = '#form.org#'                  <!--- EXPECT: CF-SQLI-001 --->
</cfquery>
