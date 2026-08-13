<cfscript>
    // CF-EVAL-001 covers both tag and script context.
    // NOTE: this comment deliberately avoids naming the sink function with
    // parentheses. The scanner does not currently skip // line comments, so
    // writing it out here would produce a finding on this line.
    v = evaluate("var" & idx);                 // EXPECT: CF-EVAL-001
</cfscript>
