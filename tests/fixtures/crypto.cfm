<!--- Real weak-algorithm usage. --->
<cfset a = hash(pw, "MD5")>                    <!--- EXPECT: CF-CRYPTO-001 --->
<cfset b = hash(pw, "SHA-1")>                  <!--- EXPECT: CF-CRYPTO-001 --->
<cfset d = createObject("java", "java.security.MessageDigest").getInstance("MD5")>  <!--- EXPECT: CF-CRYPTO-001 --->

<!--- Incidental substrings that must NOT be reported. --->
<cfset sha1Hash = readCachedDigest()>
<cfset md5sumColumn = q.md5sum>
<cfset c = hash(pw, "SHA-256")>
