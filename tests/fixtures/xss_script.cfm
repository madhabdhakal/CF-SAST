<cfscript>
    writeOutput(form.name);                    // EXPECT: CF-XSS-002
    writeOutput(encodeForHTML(url.q));
</cfscript>
