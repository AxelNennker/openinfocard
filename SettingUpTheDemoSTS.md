(Please read http://openinfocard.googlecode.com/svn/trunk/INSTALL too)

# Setting up the environment #
Let's assume you have a web application server with a 1.5 runtime (i.e. Tomcat 5.5.x). For this article, let's assume you have Tomcat isntalled at _/usr/local/apache-tomcat-5.5.20_
## Keystore Setup ##
  1. Choose a path and location for the keystore: ( _i.e. /opt/myXmldapInfocardKeystore.jks_ )
  1. generate a key using _keytool_ :
` keytool -genkey -keyalg rsa -sigalg SHA1withRSA -alias mytestKey -keystore /opt/myXmldapInfocardKeystore.jks`
    1. Enter a password: (Assuming you have not already created this keystore, choose a password for the keystore)
    1. Enter a first and last name (CN): (This should be the name of the server from which the STS will be running (i.e. _xmldap.org_ or _www.yourdomain.com_, though it will be displayed as the CN of the signing cert's subject DN)
    1. Enter an organizational unit (OU): (Again ,this can be any arbitrary name, though it will be displayed as the OU part of the signing cert's subject DN)
    1. Enter an organization name (O): (Again ,this can be any arbitrary name, though it will be displayed as the O part of the signing cert's subject DN)
    1. Enter a city (L): (Again ,this can be any arbitrary name, though it will be dispalyed as the L (for "Locality") part of the signing cert's subject DN)
    1. Enter a state name or abbreviation (ST): (Again ,this can be any arbitrary string, though it will be displayed as the ST part of the signing cert's subject DN)
    1. Enter a country code (C): (Again ,this can be any arbitrary 2-letter string, though it will be displayed as the C part of the signing cert's subject DN)
    1. _keytool_ will display the DN you have created for this key: (it should look something like: _CN=My Application, OU=Engineering, O=XMLDAP, L=San Francisco, ST=CA, C=US_ )
    1. Enter a password for 

&lt;mytestKey&gt;

: (enter as password for the newly created key)
    1. OK, now there should be a file at /opt/myXmldapInfocardKeystore.jks This is the Java keystore containing the key (mytestKey) that we created in the preceding steps
  1. add to trust chain . . .

## Building and configuring the STS WAR file ##
  1. Check out the code from SVN:
    * `svn checkout http://openinfocard.googlecode.com/svn/trunk/ openinfocard`
  1. Rename the STS properties template file
    * mv ant/sts.properties.tmpl ant/sts.properties
  1. Edit STS properties file
    * set _keystore_ to the value you chose in step 1 (i.e.  _/opt/myXmldapInfocardKeystore.jks_ )
    * set _keystore.password_ to the value you chose in step 2.1
    * set _key.name_ to the argument you passed in for the _-alias_  argument in step 2 (i.e. _mytestKey_ )
    * set _key.password_ to the value you entered in step 9