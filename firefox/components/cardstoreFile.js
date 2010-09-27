const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;
const Cu = Components.utils;

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
    },
    removeCard : function removeCard(cardId) {
    },

    // the roamingStoreXml is defined in ISIP 1.5
    addCardsFromRoamingStore : function addCardsFromRoamingStore(roamingStoreXml) {
    },

    // the informationCardXml is defined in ISIP 1.5
    updateCard : function updateCard(informationCardXml, cardId) {
    },

    getAllCardIds : function getAllCardIds(count, cardIds) {
    },

    getCardCount : function getCardCount() {
      return 0;
    },

    cardIdIterator: function cardIdIterator() {
      return null;
    },
    
    cardidIteratorNext : function cardidIteratorNext(iterator) {
      return null;
    },
    cardIdIteratorHasNext : function cardIdIteratorHasNext(iterator) {
      return true;
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
      return this.mDB;
    },
    getCardStoreVersion : function getCardStoreVersion() {
      return "1.0";
    },

    getToken : function getToken(serializedPolicy) {
      return null;
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
    
    newDB: function newDB(){
    
      var dbFile = new XML("<infocards/>");
      dbFile.version = "1";
      return dbFile;
  // cardstoreDebug("newDB start");
  // if (TokenIssuer.initialize() == true) {
  // var dbFile = TokenIssuer.newCardStore();
  // cardstoreDebug ( "New DB: " + dbFile.toString());
  // return dbFile;
  // } else {
  // cardstoreDebug("error initializing the TokenIssuer");
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
        //                                               var cardstoreXML = new XML(output);
              
              var parser = new DOMParser();
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
      consoleService.logStringMessage("CardstoreManagerService: " + msg);
    },

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
