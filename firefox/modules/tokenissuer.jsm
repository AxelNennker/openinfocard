var EXPORTED_SYMBOLS = ["TokenIssuer"];  

var TokenIssuer = {
    tokenIssuer : null,


    _alert : function(msg) {
      var data = {};
      data.msg = "Alert: " + msg;
      data.wrappedJSObject = data;

      var ww = Components.classes["@mozilla.org/embedcomp/window-watcher;1"]
                         .getService(Components.interfaces.nsIWindowWatcher);
      ww.openWindow(null, "chrome://infocard/content/alert.xul",
        "Open Information Card", "chrome,centerscreen,modal", data);
    },

    _trace : function(msg) {
      Components.classes["@mozilla.org/consoleservice;1"]
       .getService(Components.interfaces.nsIConsoleService)
            .logStringMessage(msg);
    },
    
    _fail : function(e) {
      var msg = "TokenIssuer._fail: ";
        if (e.getMessage) {
            msg = msg + e + ": " + e.getMessage() + "\n";
            while (e.getCause() !== null) {
                e = e.getCause();
                msg += "caused by " + e + ": " + e.getMessage() + "\n";
            }
        } else {
            msg = msg + e;
        }
        Components.classes["@mozilla.org/consoleservice;1"]
                           .getService(Components.interfaces.nsIConsoleService)
                                .logStringMessage(msg);
        this._alert(msg);  
    },
    
    _getExtensionPath : function(extensionName) {
        var chromeRegistry =
            Components.classes["@mozilla.org/chrome/chrome-registry;1"]
                .getService(Components.interfaces.nsIChromeRegistry);
                
        var uri =
            Components.classes["@mozilla.org/network/standard-url;1"]
                .createInstance(Components.interfaces.nsIURI);
        
        uri.spec = "chrome://" + extensionName + "/content/";
        
        var path = chromeRegistry.convertChromeURL(uri);
        if (typeof(path) == "object") {
            path = path.spec;
        }
        
        path = path.substring(0, path.indexOf("/chrome/") + 1);
        
        return path;
    },
    
    initialize : function(java) {
      try {

        TokenIssuer._trace("TokenIssuer.initialize: start");
        if (!java) {
          TokenIssuer._trace("TokenIssuer.initialize: java is not defined");
          //TokenIssuer._trace("TokenIssuer.initialize: document.location.href=" + document.location.href);
          return null;
        }
        var extensionPath = this._getExtensionPath("infocard");
        var libPath = extensionPath + "components/lib/";
        var xmldapUrl = new java.net.URL(libPath+"xmldap.jar");
        var cl = new java.net.URLClassLoader( [ xmldapUrl ]  );
        if (cl === null) {
          TokenIssuer._fail("class loader is null");
          return null;
        }
        
        var aClassName = "org.xmldap.firefox.URLSetPolicy";
        // xmldapPolicy gives us read/write permission on all files that are named cardDB.xml
        var aClass = java.lang.Class.forName(aClassName, true, cl);
        if (aClass === null) {
          TokenIssuer._trace("could not get class for " + aClassName);
          return null;
        }
        var anInstance = aClass.newInstance();
        if (anInstance === null) {
          TokenIssuer._trace("could not create instance of " + aClassName);
          return null;
        }
        anInstance.setOuterPolicy(java.security.Policy.getPolicy());
        java.security.Policy.setPolicy(anInstance);
//        var keystoreURL = new java.net.URL(extensionPath+"components/lib/firefox.jks");
        anInstance.addFilePermission(extensionPath+"components/lib/firefox.jks", "read,write");
//        var cardDbURL = new java.net.URL(extensionPath+"cardDb.xml");
        anInstance.addFilePermission(extensionPath+"cardDb.xml", "read,write");
        
        anInstance.addPermission(new java.security.SecurityPermission("putProviderProperty.BC"));
        anInstance.addPermission(new java.security.SecurityPermission("insertProvider.BC"));
        anInstance.addPermission(new java.util.PropertyPermission("org.bouncycastle.*", "read"));
        anInstance.addPermission(new java.util.PropertyPermission("jsr105Provider", "read"));

        // D:\bluecove 
        java.lang.System.setProperty("bluecove.debug.log4j", "false");
        java.lang.System.setProperty("bluecove.debug.stdout", "true");
        java.lang.System.setProperty("bluecove.native.path", "D:\\bluecove");
        java.lang.System.setProperty("bluecove.native.resource", "false");
        anInstance.addFilePermission("file:///d:/bluecove", "read,write"); //FIXME
        anInstance.addFilePermission("file:///d:/bluecove/intelbth.dll", "read"); //FIXME
        anInstance.addFilePermission("file:///d:/bluecove/bluecove.dll", "read"); //FIXME
        
        anInstance.addPermission(new java.util.PropertyPermission("bluecove.native.path", "read"));
        anInstance.addPermission(new java.util.PropertyPermission("bluecove.native.resource", "read"));
        anInstance.addPermission(new java.util.PropertyPermission("java.io.tmpdir", "read"));
        anInstance.addPermission(new java.util.PropertyPermission("user.name", "read"));
        anInstance.addFilePermission("file:///d:/DOKUME~1/NENNKE~1.AXE/LOKALE~1/Temp/bluecove_Nennker.Axel_0", "read,write"); //FIXME
        anInstance.addFilePermission("file:///d:/DOKUME~1/NENNKE~1.AXE/LOKALE~1/Temp/bluecove_Nennker.Axel_0/intelbth.dll", "read,write,delete"); //FIXME
        anInstance.addFilePermission("file:///d:/DOKUME~1/NENNKE~1.AXE/LOKALE~1/Temp/bluecove_Nennker.Axel_0/bluecove.dll", "read,write"); //FIXME
        anInstance.addPermission(new java.util.PropertyPermission("java.library.path", "read"));
        
        anInstance.addPermission(new java.lang.RuntimePermission("loadLibrary.D:\\bluecove\\intelbth.dll"));
        anInstance.addPermission(new java.lang.RuntimePermission("loadLibrary.D:\\bluecove\\bluecove.dll"));
        anInstance.addPermission(new java.lang.RuntimePermission("loadLibrary.D:\bluecove\intelbth.dll"));
        anInstance.addPermission(new java.lang.RuntimePermission("loadLibrary.D:\bluecove\bluecove.dll"));
        anInstance.addPermission(new java.lang.RuntimePermission("loadLibrary.intelbth"));
        anInstance.addPermission(new java.lang.RuntimePermission("loadLibrary.bluecove"));
        
        // anInstance.addPermission(new javax.smartcardio.CardPermission("*", "*")); // all terminals, all action
        var cpClasz = java.lang.Class.forName("javax.smartcardio.CardPermission", true, cl);
        if (cpClasz === null) {
          TokenIssuer._trace("javax.smartcardio.CardPermission is not available");
        } else {
          var cpConstructor = cpClasz.getConstructor([java.lang.Class.forName("java.lang.String"),java.lang.Class.forName("java.lang.String")]);
          if (cpConstructor === null) {
            TokenIssuer._trace("javax.smartcardio.CardPermission(String, String) is not available");
          } else {
            var cardPermission = cpConstructor.newInstance(["*", "*"]);// all terminals, all action
            if (cardPermission === null) {
              TokenIssuer._trace("javax.smartcardio.CardPermission(String, String) failed");
            } else {
              anInstance.addPermission(cardPermission);
            }
          }
        }
        
//        anInstance.addPermission(new java.security.AllPermission());
        anInstance.addURL(xmldapUrl);

        // reload the classloader
        cl = new java.net.URLClassLoader( [ xmldapUrl ]  );
        if (cl === null) {
          TokenIssuer._trace("class loader is NULL");
          return null;
        }

        var tiClass = java.lang.Class.forName("org.xmldap.firefox.TokenIssuer", true, cl);
        if (tiClass === null) {
          TokenIssuer._trace("tiClass is null");
          return null;
        }
        var tiConstructor = tiClass.getConstructor([java.lang.Class.forName("java.lang.String")]);
        if (tiConstructor === null) {
          TokenIssuer._trace("tiConstructor is null");
          return null;
        }
        
        this.tokenIssuer = tiConstructor.newInstance( [extensionPath] );
        return (this.tokenIssuer !== null);
      } catch(e) {
        this._trace("TokenIssuer.initialize threw " + e);
        return null;
      }
    },
    
    getToken : function(serializedPolicy) {
      TokenIssuer._trace("TokenIssuer.getToken " + serializedPolicy);
      return this.tokenIssuer.getToken(serializedPolicy);
    },
    
    generateRPPPID : function(serializedPolicy) {
      return this.tokenIssuer.generateRPPPID(serializedPolicy);
    },
    
    importManagedCard : function(importedCardJSONStr, cardFileJSONStr) {
      try {
        var result = this.tokenIssuer.importManagedCard(importedCardJSONStr, cardFileJSONStr);
        return result;
      } catch (e) {
        TokenIssuer._fail(e);
        }
        return null;
    },
    
    getIssuerLogoURL : function(cert) {
      try {
        var result = this.tokenIssuer.getIssuerLogoURL(cert);
        return result;
      } catch (e) {
        TokenIssuer._fail(e);
        }
        return null;
    },
    
    getWalletException : function() {
      TokenIssuer._trace("getWalletException");
      try {
        var result = this.tokenIssuer.getWalletException();
        return result;
      } catch(e) {
        TokenIssuer._fail(e);
        throw e;
      }
    },
    
    resetWalletException : function() {
      TokenIssuer._trace("resetWalletException");
      try {
        this.tokenIssuer.resetWalletException();
      } catch(e) {
        TokenIssuer._fail(e);
        throw e;
      }
    },
    
    isPhoneAvailable : function() {
      TokenIssuer._trace("isPhoneAvailable");
      try {
        var result = this.tokenIssuer.isPhoneAvailable();
        return result;
      } catch(e) {
        TokenIssuer._fail("isPhoneAvailable " + e);
        throw e;
      }
    },
    
    endCardSelection : function() {
      TokenIssuer._trace("endCardSelection");
      try {
        this.tokenIssuer.endCardSelection();
      } catch(e) {
        //TokenIssuer._fail("endCardSelection " + e);
      }
    },
    
    beginCardSelection : function() {
      TokenIssuer._trace("beginCardSelection");
      try {
        var result = this.tokenIssuer.beginCardSelection();
        return result;
      } catch(e) {
        TokenIssuer._fail(e);
        throw e;
      }
    },
    
    startCardSelection : function(serializedPolicy) {
      TokenIssuer._trace("startCardSelection: " + serializedPolicy);
      try {
        var result = this.tokenIssuer.startCardSelection(serializedPolicy);
        return result;
      } catch(e) {
        TokenIssuer._fail(e);
        throw e;
      }
    },
    
    getSelectedCard : function() {
      TokenIssuer._trace("getSelectedCard");
      try {
        var result = this.tokenIssuer.getSelectedCard();
        return result;
      } catch(e) {
        TokenIssuer._fail(e);
        throw e;
      }
    },
    
    phoneFini : function() {
      TokenIssuer._trace("phoneFini");
      try {
        this.tokenIssuer.phoneFini();
      } catch(e) {
        //TokenIssuer._fail(e);
      }
    },
    
    finalize : function() {}

};

