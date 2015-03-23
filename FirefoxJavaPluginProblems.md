# Introduction #

Sun's software engineers who implement the java plugin for Firefox are thinking in terms of java applets. They forgot to consider Firefox extensions that use java.
Therefore many thing don't work.


# Details #

If you get this error message:
"Error calling method on NPObject! [exception: java.security.AccessControlException: access denied (java.security.SecurityPermission getPolicy)](plugin.md)."

Then you are using the new plugin2 which implements java for Firefox through the plugin interface instead of the formerly used LiveConnect implementation.

What you can do to get rid of this error message: Disable plugin2!
Edit you registry as described here: http://ignisvulpis.blogspot.com/2008/11/java-again.html

Set HKEY\_LOCAL\_MACHINE\SOFTWARE\JavaSoft\Java Plug-in\1.6.0\_10\UseNewJavaPlugin from 1 to 0 to disable the new plugin.