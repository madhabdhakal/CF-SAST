<cfxml variable="doc">                            <!--- EXPECT: CF-XXE-001 --->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
</cfxml>
