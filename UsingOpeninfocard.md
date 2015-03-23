# Introduction #

To use the openinfocard selector you need a recent version of the Firefox browser, the openinfocard addon and a page that accepts information cards.


# Setting things up #

  * Download [Firefox](http://www.mozilla.com/products/download.html?product=firefox).
  * Use Firefox to go to [Addons for Firefox](https://addons.mozilla.org/en-US/firefox/addon/10292/) and install it. A restart of Firefox is required.
  * [Set a Masterpassword for Firefox](http://support.mozilla.com/en-US/kb/Protecting+stored+passwords+using+a+master+password). It will be used to encrypt your card store.

## Create a personal card ##

  * Open the options for Firefox and choose the openinfocard pane.
  * Click on "Manage Cards".
  * Click on "New Card".
  * Selector "self issued card".
  * Name the card and fill in the card values.
  * Click ok.

# Try Your Personal Card #

  * Browse to https://xmldap.org/relyingparty
  * Click on image to start the selector.
  * The selector starts...
  * Choose a card.
  * Click "ok" to use that card.
  * The xmldap.org Relyingparty displays the security token and the values that were send.

# Get a Managed Card #

  * Browse to the identity provider (IdP) of your [choice](https://xmldap.org/sts/).
  * Authenticate
  * Retrive a managed card.

> The managed card is an XML file that is signed by the identity provider.
> How you get it onto your computer does not matter. Your IdP might send it per email, you might directly download it to a local drive or whatever.

# Importing a Managed Card #

  * Open the openinfcards options pane.
  * Click on "Managed Cards".
  * Choose "New Card".
  * Select "managed card".
  * Select the file that contains the managed card you got from your IdP.
  * Click "ok".

> The openinfocard selector will read the file, validate the IdP's signature and then convert the card into an internal format that will be stored into the local cardstore.

# Creating an OpenID card #

  * Open the openinfcards options pane.
  * Click on "Managed Cards".
  * Choose "New Card".
  * Select "openid".
  * Enter your openid.
  * Click "ok" to save the card.

# Using your OpenID card #

  * Browse to a site that accepts OpenID cards.
    * https://www.plaxo.com/signin?test.selector=1
    * http://test-id.org/XP/selector.aspx
    * https://xmldap.org/xmldap_oc/