<cfscript>
    // Bound parameters via the params argument. No finding expected.
    q = queryExecute("SELECT * FROM users WHERE id = :id", { id: url.id });
</cfscript>
