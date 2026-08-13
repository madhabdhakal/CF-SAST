<!--- Encoded output must not be reported. --->
<cfoutput>
    Hello #EncodeForHTML(form.name)#
    You searched for #encodeForHtml(url.q)#
</cfoutput>
