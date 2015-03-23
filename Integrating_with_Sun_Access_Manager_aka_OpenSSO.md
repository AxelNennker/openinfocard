# Introduction #

In October 2006 I wrote a simple LoginModule for SUN's Access Manager (opensso) which uses openinfocard to decrypt the xmltoken and authenticate him by his infocard. The LoginModule is very basic, but can be extended to be usefull (I guess). Currently it accepts users by their email address and a fixed password. This **SHOULD** be changed to PPID and the Modulus (or the hash thereof) found in the decrypted token. If the login is successfull you are redirected to a demo shop website (which IP address you don't know). You have to change this behaviour in the java code.
**Remember this is a demo -> NO WARRANTY.**

http://openinfocard.googlecode.com/svn/trunk/AccessManager-LoginModulInfocard/


# Installation #

  * Get the code from the svn repository
  * Edit the Makefile to adopt to your Access Manager intallation
  * Edit the java file to change the "password" and "userTokenId"-claim
  * run make (/usr/ccs/bin/make)
  * run make deploy
> > This copies the files to your Access Manager installation
  * redeploy Access Manager (amsilent stuff)
  * stop and start the webserver
  * login as administrator to amserver and add a user
  * navigate your favorite browser to your Access Manager website
> > e.g.: https://n1v1.e1.i3alab.net/amserver/UI/Login?module=LoginInfoCard

**Please note: The makefile copies your webserver's private key to the alias directory. This may not what you want**. This is because the standard Sun One webserver uses the [NSS](http://www.mozilla.org/projects/security/pki/nss/) library to implement [SSL](http://www.mozilla.org/projects/security/pki/nss/ssl/). There is **NO** way to retrieve the private key from a NSS keystore. The private key is needed to [decrypt the xml token](http://xmldap.blogspot.com/2006/03/how-to-consume-tokens-from-infocard.html) because the [Cardspace](http://msdn2.microsoft.com/en-us/netframework/aa663320.aspx) identity selector encrypted the token using the webserver's public key. You could configure the webserver to use a java keystore and change the code to retrieve the key from it.

# Some Pictures #

![http://openinfocard.googlecode.com/svn/trunk/AccessManager-LoginModulInfocard/loginpage.png](http://openinfocard.googlecode.com/svn/trunk/AccessManager-LoginModulInfocard/loginpage.png)

If you click on the "card" the infocard selector should be launched.

![http://openinfocard.googlecode.com/svn/trunk/AccessManager-LoginModulInfocard/infocard-selector.png](http://openinfocard.googlecode.com/svn/trunk/AccessManager-LoginModulInfocard/infocard-selector.png)






