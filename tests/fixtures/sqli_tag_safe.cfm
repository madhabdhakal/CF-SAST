<!--- Fully parameterized. Interpolation appears only inside cfqueryparam
      value attributes, which is safe. No finding expected anywhere. --->
<cfquery name="safeUser" datasource="ds">
    SELECT * FROM users
    WHERE id = <cfqueryparam value="#url.id#" cfsqltype="cf_sql_integer">
      AND org = <cfqueryparam value="#form.org#" cfsqltype="cf_sql_varchar">
</cfquery>
