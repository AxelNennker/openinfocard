# Introduction #

This project contains several parts:

  * a Firefox addon https://addons.mozilla.org/en-US/firefox/addon/10292/
  * a java library called xmldap-1.0.jar
  * the code for the xmldap.org STS and relyingparty and of several other example web apps

# Details #

## The Java Library ##

  * The xmldap-1.0.jar file contains the java classes to implement the STS, the relyingparty and the tokenissuer needed by the openinfocard Firfox addon.
  * The security token server code is in the files below this directory [src/org/xmldap/sts](http://code.google.com/p/openinfocard/source/browse/#svn/trunk/src/org/xmldap/sts).

  * The library contains code to
    * create SAML assertions
    * sign XML
    * sign SAML
    * validate XML signatures
    * do the crypto stuff needed for the SAML tokens
    * handle the ASN.1 stuff of extended validation certificates like extract the community icon

  * code that is not very much used is e.g.:
    * code for RoamingInformationCards
    * cardstore code

  * The code for the JUNIT tests are in the folder "testsrc".
> > If you hack on the library code please run the tests and provide new ones for your code.

## The xmldap.org applications ##

  * The relying party jsp pages are in [websrc/xmldap\_rp](http://code.google.com/p/openinfocard/source/browse/#svn/trunk/websrc/xmldap_rp)
  * The STS jsp pages are in [websrc/xmldap\_sts](http://code.google.com/p/openinfocard/source/browse/#svn/trunk/websrc/xmldap_sts)

## The Firefox Addon ##

  * The code for the Firefox addon is in the [firefox folder](http://code.google.com/p/openinfocard/source/browse/#svn/trunk/firefox).

### Structure of the Firefox addon ###

  * Read the install.rdf and the chrome.manifest
  * The components folder contains the code the runs first. This code code is used to set things up and provide a safe anchor for other parts of the code that need to register something - like openid listeners and card stores. It also contains the idl files that define how components can be accessed by other code.
  * The contents folder contains the ["selector selector"](http://code.google.com/p/openinfocard/source/browse/trunk/firefox/chrome/infocard/content/IdentitySelector.js) and the selector(s) and the "Add Card" [wizard](http://code.google.com/p/openinfocard/source/browse/trunk/firefox/chrome/infocard/content/cardWizard.js) and the "Card Management" ([cardManager.xul](http://code.google.com/p/openinfocard/source/browse/trunk/firefox/chrome/infocard/content/cardManager.xul))

#### The Selector Selector ####


> This is the central part of the openinfocard addon.
> It sets all the handlers and parses the loaded webpage to determine whether an object tag of type "application/x-informationcard" is part of the page.
> The actual selector is started from this code.

> Currently implemented selectors are:
  * The openinfocard selector (cardManager.xul)
  * The Phone selector (not opensource)
> A HBX selector is planned.