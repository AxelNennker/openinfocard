# Introduction #

The xmldap id selector for Firefox currently only support username/password authentication at the IdP/STS.

We need code to support the other three UserCredential-types.


  * Self-issued Token Credential
  * X.509v3 Certificate Credential
  * Kerberos v5 Credential


# Details #

The file to be improved is
http://openinfocard.googlecode.com/svn/trunk/firefox/chrome/infocard/content/infocards.js

I prepared the function "processManagedCard" to detect the different usercredentials, but the code for the other three type is missing.

**The code at the server side is missing too**


Changes need to be introduced here (currently):
http://openinfocard.googlecode.com/svn/trunk/src/org/xmldap/sts/servlet/STSServlet.java

I will move some of the methods from this class to a sts/Utils.java class soon and might forget to update this wiki page then...

