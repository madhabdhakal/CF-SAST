<cfoutput>
    Hello #form.name#                          <!--- EXPECT: CF-XSS-001 --->
    You searched for #url.q#                   <!--- EXPECT: CF-XSS-001 --->
</cfoutput>
