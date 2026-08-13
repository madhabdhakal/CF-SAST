<!--- filter= must stay on the opening-tag line and ahead of any marker: the
      rule scans from <cfldap to filter= without crossing a ">". --->
<cfldap server="ldap.example.com" action="query" name="r" filter="(uid=#url.user#)"  <!--- EXPECT: CF-LDAP-001, CF-XSS-001 --->
        start="dc=example,dc=com">
