<!--- A safe query followed by an unsafe one. A greedy or block-confused
      matcher will either miss the second or blame the first. --->
<cfquery name="first" datasource="ds">
    SELECT id FROM t WHERE k = <cfqueryparam value="#url.k#" cfsqltype="cf_sql_integer">
</cfquery>

<cfquery name="second" datasource="ds">
    SELECT id FROM t WHERE k = #url.k#        <!--- EXPECT: CF-SQLI-001 --->
</cfquery>
