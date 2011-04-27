const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;
const Cu = Components.utils;

const nsIX509Cert = Ci.nsIX509Cert;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");

function OicCardstoreFile() {
  // If you only need to access your component from Javascript, uncomment the following line:
  this.wrappedJSObject = this;
}

OicCardstoreFile.prototype = {
    // properties required for XPCOM registration:
    classDescription: "The openinfocard cardstore in a local file implementation",
    classID:          Components.ID("{bdc78940-db54-11de-8a39-0800200c9a66}"),
    contractID:       "@openinfocard.org/cardstore-file;1",
    _xpcom_categories: [{  
           category: "information-card-storage",
           entry: "@openinfocard.org/cardstore-file;1",
           service: true  
    }],  
    // QueryInterface implementation
    QueryInterface: XPCOMUtils.generateQI([Ci.IInformationCardStore,
                                           Ci.nsISupports]),

    mDB: "cardDb.xml",
    
    errorstring: "",
    errornumber: 0,

    /* returns true on success */
    login : function login(credentials) {
      return true;
    },
    
    logout : function logout() {
    },

    loggedIn : function loggedIn() {
      return true;
    },


    clearCardStore : function clearCardStore() {
    },

    // the informationCardXml is defined in ISIP 1.5
    addCard : function addCard(informationCardXml) {
      try {
        var card = new XML(informationCardXml); // from xpcom string to xml
        var cardFile = this.read(this.mDB);
        cardFile.infocard += card;
        this.save(this.mDB,cardFile.toXMLString());
      } catch (e) {
        this.log("addCard exception: " + e);
        throw e;
      }
    },
    removeCard : function removeCard(cardId) {
      var cardFile = this.read(this.mDB);
      var count = 0;
      for each (c in cardFile.infocard) {
          var latestId = c.id;
          if (latestId == cardId) delete cardFile.infocard[count];
          count++;
      }
      this.save(this.mDB,cardFile.toXMLString());
    },

    // the roamingStoreXml is defined in ISIP 1.5
    addCardsFromRoamingStore : function addCardsFromRoamingStore(roamingStoreXml) {
    },

    // the informationCardXml is defined in ISIP 1.5
    updateCard : function updateCard(informationCardXml, cardId) {
      var card = new XML(informationCardXml); // from xpcom string to xml
      var cardFile = this.read(this.mDB);
      var nDB = this.newDB();
      
      for each (c in cardFile.infocard) {
          var latestId = c.id;
          if (latestId == card.id) {
           nDB.infocard += card;
          } else {
           nDB.infocard += c;
          }
      }
      this.save(this.mDB,nDB.toXMLString());
    },

    getAllCardIds : function getAllCardIds(count, cardIds) {
      var cardFile = this.read(this.mDB);
      for each (c in cardFile.infocard) {
          var latestId = c.id;
          cardIds.push(latestId);
          count++;
      }
    },

    getCardCount : function getCardCount() {
      var count = 0;
      var cardFile = this.read(this.mDB);
      for each (c in cardFile.infocard) {
        count++;
      }
      return count;
    },

    //    nsISimpleEnumerator getInformationCards();
    getInformationCards : function getInformationCards() {
      return new CardEnumerator();
    },
    
    // returns an encrypted card store as defined in ISIP 1.5
    cardStoreExportAllCards : function cardStoreExportAllCards(password) {
      return null;
    },
    cardStoreExportCards : function cardStoreExportCards(password, count, cardIds) {
      return null;
    },

    // this may return null if this cardStore is not willing to reveal the mastersecret
    getMasterSecretForCard : function getMasterSecretForCard(cardId) {
      return null;
    },
    
    getRpIdentifier : function getRpIdentifier(cardId, relyingPartyCertificate) {
      return null;
    },
    
    getCardByPPID : function getCardByPPID(PPID, relyingPartyCertificate) {
      return null;
    },

    getCardStoreName : function getCardStoreName() {
      return "openinfocard"; //this.mDB;
    },
    getCardStoreVersion : function getCardStoreVersion() {
      return "1.0";
    },

    getDer : function getDer(cert,win){
      var length = {};
      var derArray = cert.getRawDER(length);
      var certBytes = '';
      for (var i = 0; i < derArray.length; i++) {
          certBytes = certBytes + String.fromCharCode(derArray[i]);
      }
      return win.btoa(certBytes);
    },

    GetBrowserToken: function (
        issuer , recipientURL, requiredClaims, optionalClaims , tokenType, 
        privacyPolicy, privacyPolicyVersion, serverCert, issuerPolicy, 
        extraParamsLenght, extraParams) {

       this.log('issuer: ' + issuer);
       this.log('recipientURL: ' + recipientURL);
       if (requiredClaims !== null) {
         requiredClaims = requiredClaims.replace(/\s+/g,' ');
       }
       this.log('requiredClaims: ' + requiredClaims);
       if (optionalClaims !== null) {
         optionalClaims = optionalClaims.replace(/\s+/g,' ');
       }
       this.log('optionalClaims: ' + optionalClaims);
       this.log('tokenType: ' + tokenType);
       this.log('privacyPolicy: ' + privacyPolicy);
       this.log('privacyPolicyVersion: ' + privacyPolicyVersion);
       this.log('serverCert: ' + serverCert);
       this.log('issuerPolicy: ' + issuerPolicy);
       this.log('extraParamsLenght: ' + extraParamsLenght);

       var callback;

       var policy = {};
       if (tokenType) {
         policy.tokenType = tokenType;
       }
       if (issuer) {
         policy.issuer = issuer;
       }
       if (requiredClaims) {
         policy.requiredClaims = requiredClaims;
       }
       if (optionalClaims) {
         policy.optionalClaims = optionalClaims;
       }
       if (privacyPolicy) {
         policy.privacyUrl = privacyPolicy;
       }
       if (privacyPolicyVersion) {
         policy.privacyVersion = privacyPolicyVersion;
       }
       if (issuerPolicy) {
         policy.issuerPolicy = issuerPolicy;
       }
       if (extraParamsLenght) {
         policy.extraParamsLenght = extraParamsLenght;
       }
       if (extraParams) {
         policy.extraParams = extraParams;
       }

       //get a handle on a window
       var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"].getService(Components.interfaces.nsIWindowMediator);
       var win = wm.getMostRecentWindow("navigator:browser");

       var mwNode = win.document.getElementById("main-window");
       if (mwNode) {
         if (mwNode.style.backgroundImage) {
           policy.backgroundImage = mwNode.style.backgroundImage;
           this.log('backgroundImage: ' + mwNode.style.backgroundImage);
         }
       }
       
       if (serverCert !== null) {
         policy.cert = this.getDer(serverCert,win);
         policy.cn = serverCert.commonName;

         var chain = serverCert.getChain();
         this.log('chain: ' + chain);
         this.log('chainLength: ' + chain.length);
         this.log('chain[0]: ' + chain.queryElementAt(0, nsIX509Cert));

         policy.chainLength = ""+chain.length;
         for (var i = 0; i < chain.length; ++i) {
           var currCert = chain.queryElementAt(i, nsIX509Cert);
           policy["certChain"+i] = this.getDer(currCert,win);
         }
//         debugObject("serverCert: ", serverCert, 0);
       }

           // win.document.URL is undefined
           // win.document.location.href is chrome://.../browser.xul
       policy.url = recipientURL; 

       if ("urn:oasis:names:tc:IC:1.0:managedcard" == tokenType) {
         var cardWiz = win.openDialog("chrome://infocard/content/cardWizard.xul","Card Wizard", "modal,chrome,resizable=yes,width=640,height=480",
                   policy, function (callbackData) { callback = callbackData;});
         
       } else {
             var cardManager = win.openDialog("chrome://infocard/content/cardManager.xul","InfoCard Selector", "modal,chrome,resizable,width=800,height=640,centerscreen", policy, function (callbackData) { callback = callbackData;});
             var doc = win.document;
             var event = doc.createEvent("Events");
             event.initEvent("CloseIdentitySelector", true, true);
             win.dispatchEvent(event);
     
             this.log('Token: ' + callback);
       }

       return callback;

  },

  getToken : function getToken(serializedPolicy) {
    var policy = JSON.parse(serializedPolicy);
    
    var token = this.GetBrowserToken(policy.issuer,
        policy.recipient, policy.requiredClaims,
        policy.optionalClaims, policy.tokenType, policy.privacyUrl,
        policy.privacyVersion, policy.sslCert, policy.issuerPolicy,
        policy.extraParamsLength, policy.extraParams);

    return token;
  },

  getDir : function getDir() {
    var path;
  
    // get the path to the user's home (profile) directory
    const DIR_SERVICE = new Components.Constructor("@mozilla.org/file/directory_service;1","nsIProperties");
    try {
        path=(new DIR_SERVICE()).get("ProfD", Components.interfaces.nsIFile).path;
    } catch (e) {
        this.log("error: " + e);
        throw e;
    }
    // determine the file-separator
    if (path.search(/\\/) != -1) {
        path = path + "\\";
    } else {
        path = path + "/";
    }
    
    return path;
  },
    
    readALocalFile: function readALocalFile(fileName) {

      var file = Components.classes["@mozilla.org/file/local;1"].createInstance(Components.interfaces.nsILocalFile);
      file.initWithPath( fileName );
      
      if ( file.exists() === false ) {
        this.log("readALocalFile: " + fileName + " not found.");
          return null;
      }
      
      var output = null;
      
      var is = null;
      try {
        is = Components.classes["@mozilla.org/network/file-input-stream;1"].createInstance( Components.interfaces.nsIFileInputStream );
        is.init( file,0x01, 4, null);
        var sis = null;
        try {
          sis = Components.classes["@mozilla.org/scriptableinputstream;1"].createInstance( Components.interfaces.nsIScriptableInputStream );
          sis.init( is );
          output = sis.read( sis.available() );
        } catch (e) {
          this.log("readALocalFile threw exception " + e);
          if (sis !== null) {
            sis.close();
          }
        } finally {
          if (sis !== null) {
            sis.close();
          }
        }
      } catch (ee) {
        this.log("readALocalFile threw an exception " + ee);
             if (is !== null) {
               is.close();
             }
           } finally {
             if (is !== null) {
               is.close();
             }
      }
      return output;
    },
    
    saveLocalFile: function saveLocalFile(fileName, contents) {
      
      var file = Components.classes["@mozilla.org/file/local;1"].createInstance(Components.interfaces.nsILocalFile);
      file.initWithPath( fileName );
      if ( file.exists() === false ) {
        file.create( Components.interfaces.nsIFile.NORMAL_FILE_TYPE, 420 );
      }
      var outputStream = Components.classes["@mozilla.org/network/file-output-stream;1"].createInstance( Components.interfaces.nsIFileOutputStream );
      try {
        outputStream.init( file, 0x04 | 0x08 | 0x20, 420, 0 );
        
        var charset = "UTF-8"; // Can be any character encoding name that Mozilla
                                // supports
      
        var converter = Components.classes["@mozilla.org/intl/converter-output-stream;1"]
                         .createInstance(Components.interfaces.nsIConverterOutputStream);
        try {
          converter.init(outputStream, charset, 0, 0x0000);
          converter.writeString(contents);
        }
        finally {
          converter.close();
        }
      }
      finally {    
          //var result = outputStream.write( fileContents, fileContents.length );
               outputStream.close();
           }
    },
    
    save: function _save(fileName, fileContents) {
      var prefs = Components.classes["@mozilla.org/preferences-service;1"].
                  getService(Components.interfaces.nsIPrefService);
      prefs = prefs.getBranch("extensions.infocard.");
  
      var encrypt = prefs.getBoolPref("cardStoreMasterPasswordEncryption");
      if (encrypt) {
          var sdr = Components.classes["@mozilla.org/security/sdr;1"]
                                  .getService(Components.interfaces.nsISecretDecoderRing);
          fileContents = sdr.encryptString(fileContents);
      }    
  
      var useProfile = prefs.getBoolPref("cardStoreCurrentProfile");
      if (useProfile) {
          this.log("saving profile cardstore");
              fileName = this.getDir() + fileName;
              this.saveLocalFile(fileName, fileContents);
              return;
      }
  
      var localFilePath = prefs.getComplexValue("cardStoreLocalFilePath",
                                  Components.interfaces.nsISupportsString).data;
      if ((localFilePath != null) && (localFilePath != "")) {
              this.log("using local file as cardstore: " + localFilePath);
              try {
                  this.saveLocalFile(localFilePath, fileContents);
                  return;
              } catch(e) {
                  this.log("cardstore.js writing local file cardstore failed:" + e);
              } 
              return;
      }

      var url = prefs.getComplexValue("cardStoreUrl", Components.interfaces.nsISupportsString).data;
      if ((url != null) && (url != "")) {
              this.log("writing url cardstore: " + url);
              var req = new XMLHttpRequest();
              req.open('POST', url, false);
              req.setRequestHeader("Content-type", "application/xml; charset=utf-8");
              req.setRequestHeader("Cache-Control", "no-cache");
              req.setRequestHeader("User-Agent", "xmldap infocard stack");
              req.send(fileContents);
          this.log("POST request status="+req.status);
          if(req.status == 200) {
            return;
          } else {
            this.log("cardstore.js" + req.responseText);    
            return;
          }
      }
      this.log("cardstore.js writing cardstore failed");
  },
    
    newDB: function newDB(){
    
      var dbFile = new XML("<infocards/>");
      dbFile.version = "1";
      return dbFile;
  // this.log("newDB start");
  // if (TokenIssuer.initialize() == true) {
  // var dbFile = TokenIssuer.newCardStore();
  // this.log ( "New DB: " + dbFile.toString());
  // return dbFile;
  // } else {
  // this.log("error initializing the TokenIssuer");
  // return null;
  // }
     },
    
     readLocalFile : function readLocalFile(fileName) {
       try {
         this.log("readLocalFile: reading: " + fileName);
    
         var output = this.readALocalFile(fileName);
         if (output === null) {
           this.log("readALocalFile returned null: " + fileName);
           return this.newDB();
         }
      
         if (!output) {
           output = this.newDB();
         } else {
           var prefs = Components.classes["@mozilla.org/preferences-service;1"].
                  getService(Components.interfaces.nsIPrefService);
           prefs = prefs.getBranch("extensions.infocard.");
           var encrypt = prefs.getBoolPref("cardStoreMasterPasswordEncryption");
           var sdr;
           if (encrypt) {
                sdr = Components.classes["@mozilla.org/security/sdr;1"]
                                .getService(Components.interfaces.nsISecretDecoderRing);
                var decrypted = "";
                try {
                decrypted = sdr.decryptString(output);
                } catch (e) {
                  try {
                    this.log(e + "\nerror decypting the cardstore: " + fileName);
                      return new XML(output);
                  } catch (ee) {
                    this.log(ee + "\ndeencrypted cardstore is no valid xml: " + fileName);
                    return this.newDB();
                  }
                }
            
              //this.log(decrypted);
              return new XML(decrypted);
          } else {
            var cardstoreXML;
            try {
              var parser = Components.classes["@mozilla.org/xmlextras/domparser;1"]
                                      .createInstance(Components.interfaces.nsIDOMParser);
              var dom = parser.parseFromString(output, "text/xml");
              if (dom.documentElement.nodeName == "parsererror") {
                throw "parseerror";
              } else {
                cardstoreXML = new XML(Components.classes['@mozilla.org/xmlextras/xmlserializer;1'].createInstance(Components.interfaces.nsIDOMSerializer).serializeToString(dom.documentElement));
                return cardstoreXML;
              }
        
              this.log("unencrypted cardstore: " + cardstoreXML);
              return cardstoreXML;
            }
            catch (ee) {
              this.log(ee + "\nunencrypted cardstore is no valid xml:\n" + output);
              // try to decrypt
                    sdr = Components.classes["@mozilla.org/security/sdr;1"]
                                    .getService(Components.interfaces.nsISecretDecoderRing);
                    var decrypted = "";
                    try {
                      decrypted = sdr.decryptString(output);
                      this.log("decrypted cardstore:\n" + decrypted);
                      try {
                        var cardstoreXML = new XML(Components.classes['@mozilla.org/xmlextras/xmlserializer;1'].createInstance(Components.interfaces.nsIDOMSerializer).serializeToString(decrypted));
              
                        this.log("Unencrypted cardstore: " + cardstoreXML);
                        this.saveLocalFile(fileName, cardstoreXML); // save decrypted card
                                                                    // store
                        return cardstoreXML;
                      } catch (e) {
                        this.log(e + "Error reading XML:\n" + decrypted);
                        try {
                          // new XML is less picky than xmlserializer
                          cardstoreXML = new XML(decrypted);
                          this.saveLocalFile(fileName, cardstoreXML); // save decrypted
                                                                      // card store
                          return cardstoreXML;
                        } catch (e) {
                          this.log(e + "Error Reading XML:\n" + decrypted);
                          return this.newDB();
                        }
                        return this.newDB();
                      }
                    } catch (e) {
                      this.log("Error decrypting the cardstore:\n" + output);
                      return this.newDB();
                    }
              }
               }
               }
               var dbFile = new XML(output);
               return dbFile;
       } catch (readLocalFileException) {
         this.log("readLocalFile Exception: " + readLocalFile);
       }
     },
    
    read : function read(fileName) {
         var prefs = Components.classes["@mozilla.org/preferences-service;1"].
                    getService(Components.interfaces.nsIPrefService);
      prefs = prefs.getBranch("extensions.infocard.");
      
      var useProfile = prefs.getBoolPref("cardStoreCurrentProfile");
      if (useProfile) {
          fileName = this.getDir() + fileName;
          this.log("using profile cardstore: " + fileName);
        return this.readLocalFile(fileName);
      }
      
      var localFilePath = prefs.getComplexValue("cardStoreLocalFilePath",
        Components.interfaces.nsISupportsString).data;
      if ((localFilePath != null) && (localFilePath != "")) {
          this.log("using local file as cardstore: " + localFilePath);
          try {
            return this.readLocalFile(localFilePath);
          } catch(e) {
            this.log("reading local file cardstore failed:" + e);
            throw e;
          } 
          return new XML(this.newDB());
      }
      
      var url = prefs.getComplexValue("cardStoreUrl",
        Components.interfaces.nsISupportsString).data;
      if ((url != null) && (url != "")) {
          this.log("using url cardstore: " + url);
          var req = new XMLHttpRequest();
          req.open('GET', url, false);
      // req.setRequestHeader("Content-type", "application/xml; charset=utf-8");
          req.setRequestHeader("Cache-Control", "no-cache");
          req.setRequestHeader("User-Agent", "xmldap infocard stack");
          req.send(null);
          this.log("GET request status="+req.status);
          if(req.status == 200) {
            try { // try to decrypt
              var decrypted = "";
                  var sdr = Components.classes["@mozilla.org/security/sdr;1"]
                              .getService(Components.interfaces.nsISecretDecoderRing);
                  decrypted = sdr.decryptString(req.responseText);
                  return new XML(decrypted);
            }
            catch (e) {
              this.log("decrypting cardstore returned from " + url + " failed");
              try {
                return new XML(req.responseText);
              }
              catch (e) {
                this.log("no valid xml returned from " + url);
                return new XML(this.newDB());
              }
            }
        } else {
          this.log("req.status = " + req.status);
          this.log("req.responseText=" + req.responseText);    
            return new XML(this.newDB());
          }
      }
      
      this.log("reading cardstore failed");
             return new XML(this.newDB());
    },
    
    readCardStore: function readCardStore() {
         var cardFile = this.read(this.mDB);
        // this.log("readCardStore:" + cardFile);
         return cardFile;
    },
    
    isCardInStore : function isCardInStore(cardId) {
      var cardFile = this.readCardStore();
      for each (c in cardFile.infocard) {
        if ("" + c.id === cardId) {
          return true;
        }
      }
      return false;
    },
    
    log: function _log(msg) {
      var consoleService = Cc[ "@mozilla.org/consoleservice;1"].getService(Ci.nsIConsoleService);
      consoleService.logStringMessage("cardstoreFile: " + msg);
    }

};

function CardEnumerator() {
  this.index = 0;
  this.cardFile = this.readCardStore();
}

CardEnumerator.prototype.QueryInterface = function(iid) {
  if (iid.equals(Components.interfaces.nsISupports) ||
      iid.equals(Components.interfaces.nsISimpleEnumerator))
    return this;
  throw Components.results.NS_NOINTERFACE;
};

CardEnumerator.prototype.getNext = function() {
  return this.cardFile.infocard[this.index++];
};

CardEnumerator.prototype.hasMoreElements = function() {
  return (this.index < this.cardFile.length());
};

/**
* XPCOMUtils.generateNSGetFactory was introduced in Mozilla 2 (Firefox 4).
* XPCOMUtils.generateNSGetModule is for Mozilla 1.9.2 (Firefox 3.6).
*/
if (XPCOMUtils.generateNSGetFactory) {
  var NSGetFactory = XPCOMUtils.generateNSGetFactory([OicCardstoreFile]);
} else {
  var NSGetModule = XPCOMUtils.generateNSGetModule([OicCardstoreFile]);
}
