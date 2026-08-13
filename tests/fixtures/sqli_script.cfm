<cfscript>
    // String-concatenated SQL passed to queryExecute.
    q = queryExecute("SELECT * FROM users WHERE id = " & url.id);   // EXPECT: CF-SQLI-002
</cfscript>
