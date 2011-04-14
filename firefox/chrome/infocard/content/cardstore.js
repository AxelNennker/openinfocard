Components.utils.import("resource://infocard/tokenissuer.jsm");
Components.utils.import("resource://infocard/OICCrypto.jsm");
Components.utils.import("resource://infocard/IdentitySelectorDiag.jsm");

function readCardStore() {
  var aCardstore = InformationCardHelper.getCardstore();
  if (!aCardstore) {
    IdentitySelectorDiag.reportError( "cardstore.js readCardStore",
              "Unable to locate a card store.  " +
              "Please make sure one is installed.");
    return null;
  }
  var cardFile = aCardstore.readCardStore();
  return cardFile;
}

function isCardInStore(cardId) {
  cardstoreDebug("cardstore.js: isCardInStore cardId=" + cardId);
  try {
    var aCardstore = InformationCardHelper.getCardstore();
    if (!aCardstore) {
      IdentitySelectorDiag.reportError( "cardstore.js readCardStore",
                "Unable to locate a card store.  " +
                "Please make sure one is installed.");
      return null;
    }
    return aCardstore.isCardInStore(cardId);
  } catch (e) {
    cardstoreDebug("cardstore.js: isCardInStore threw: " + e);
    throw e;
  }
}

function clearOpeninfocardHistory() {
    var cardFile = readCardStore();
    var nDB = newDB();
    
    for each (c in cardFile.infocard) {
      delete c.rpIds;
      dump("clearOpeninfocardHistory: " + c.id);
      nDB.infocard += c;
    }
    save(db,nDB.toString());
}

function saveRoamingStore(roamingstore) {
  //saveLocalFile(getDir() + "roamingstore.xml", roamingstore);
  save("roamingstore.xml", roamingstore);
}

function readRoamingStore() {
  return readALocalFile(getDir() + "roamingstore.xml");
}

function getCard(cardid){
//  cardstoreDebug("storeCard: cardid=" + cardid);
//  cardstoreDebug("storeCard: typeof(cardid)=" + typeof(cardid));
  var cardFile = readCardStore();
  cardstoreDebug("getCard: typeof(cardFile)=" + typeof(cardFile));
  if (typeof(cardFile) == "string") {
    cardFile = new XML(cardFile);
  }
//  cardstoreDebug("storeCard: cardFile=" + cardFile);
//  cardstoreDebug("storeCard: typeof(cardFile)=" + typeof(cardFile));
//  cardstoreDebug("storeCard: typeof(cardFile.infocard)=" + typeof(cardFile.infocard));
    
    for each (c in cardFile.infocard) {
      if (c.id == cardid) {
        cardstoreDebug("getCard: c.id=" + c.id + "==" + cardid);
        return c;
      } else {
        cardstoreDebug("getCard: c.id=" + c.id + "!=" + cardid);
      }
    }
    return null;
// the following line stopped to work in Firefox 3.1    
//    var card = cardFile.infocard.(id == cardid);
//    return card;
}

function storeCard(card){
cardstoreDebug("storeCard");
cardstoreDebug(card);
  if (card === undefined) {
    throw "storeCard: internal error: the card is undefined";
  }
  var aCardstore = InformationCardHelper.getCardstore();
  if (!aCardstore) {
    IdentitySelectorDiag.reportError( "cardstore.js storeCard",
              "Unable to locate a card store.  " +
              "Please make sure one is installed.");
  }
  aCardstore.storeCard(card);
}

function removeCard(selectedCardId) {
  var aCardstore = InformationCardHelper.getCardstore();
  if (!aCardstore) {
    IdentitySelectorDiag.reportError( "cardstore.js storeCard",
              "Unable to locate a card store.  " +
              "Please make sure one is installed.");
  }
  aCardstore.removeCard(selectedCardId);
}

// make a copy of the db replacing one card
function updateCard(card) {
  var aCardstore = InformationCardHelper.getCardstore();
  if (!aCardstore) {
    IdentitySelectorDiag.reportError( "cardstore.js storeCard",
              "Unable to locate a card store.  " +
              "Please make sure one is installed.");
  }
  aCardstore.updateCard(card);
}

function login(cardStorePath) {
  // Get Password Manager (does not exist in Firefox 3)
  var CC_passwordManager = Components.classes["@mozilla.org/passwordmanager;1"];
  var CC_loginManager = Components.classes["@mozilla.org/login-manager;1"];
     
  if (CC_passwordManager != null) {
      // Password Manager exists so this is not Firefox 3 (could be Firefox 2, Netscape, SeaMonkey, etc).
      // Password Manager code
      // the host name of the password we are looking for
    var queryString = 'chrome://infocard/cardstore?' + encodeURIComponent(cardStorePath);
    // ask the password manager for an enumerator:
    var e = passwordManager.enumerator;
    // step through each password in the password manager until we find the one we want:
    while (e.hasMoreElements()) {
        try {
            // get an nsIPassword object out of the password manager.
            // This contains the actual password...
            var pass = e.getNext().QueryInterface(Components.interfaces.nsIPassword);
            if (pass.host == queryString) {
                 // found it!
//                 alert(pass.user); // the username
//                 alert(pass.password); // the password
                 break;
            }
        } catch (ex) {
            // do something if decrypting the password failed--probably a continue
        }
    }
  }
  else if (CC_loginManager!= null) {
     // Login Manager exists so this is Firefox 3
     // Login Manager code
     IdentitySelectorDiag.reportError("cardstore.js", "loginManager support is not implemented.");
  }
}

// http://forums.mozillazine.org/viewtopic.php?p=921150#921150
function getContents(aURL){
  var str = null;
  var ioService=Components.classes["@mozilla.org/network/io-service;1"]
    .getService(Components.interfaces.nsIIOService);
  var scriptableStream=Components
    .classes["@mozilla.org/scriptableinputstream;1"]
    .getService(Components.interfaces.nsIScriptableInputStream);
  try {
    var channel=ioService.newChannel(aURL,null,null);
    var input=channel.open();
    try {
      scriptableStream.init(input);
      
      var length; 
    
      if (channel.contentLength > 0)
        length = channel.contentLength;
      else
        length = input.available();
         
      str = "";
      while (str.length < length)
        str += scriptableStream.read(length - str.length);
    }
    finally {
    input.close();
    }
  }
  finally {
  scriptableStream.close();
  }
  return str;
} 


function getDir(){
    var path;

    // get the path to the user's home (profile) directory
    const DIR_SERVICE = new Components.Constructor("@mozilla.org/file/directory_service;1","nsIProperties");
    try {
        path=(new DIR_SERVICE()).get("ProfD", Components.interfaces.nsIFile).path;
    } catch (e) {
        IdentitySelectorDiag.reportError("cardstore.js", "error");
    }
    // determine the file-separator
    if (path.search(/\\/) != -1) {
        path = path + "\\";
    } else {
        path = path + "/";
    }

    return path;

}

function newInfocard(){
    var card = new XML("<infocard/>");
    return card;
}

function newManagedCard(callback) {
    var card = newInfocard();
    card.name = "" + callback.cardName + "";
    card.type = "" + callback.type;
    card.version = "" + callback.cardVersion + "";
    card.id = "" + callback.cardId + "";

    var data = new XML("<managed/>");
    data.issuer = "" + callback.issuer + "";
    if (callback.cardImage !== undefined) {
      if (callback.cardImageMimeType === undefined) {
        data.image = "data:image/png;base64," + callback.cardImage + "";
      } else {
        data.image = "data:" + callback.cardImageMimeType + ";base64," + callback.cardImage + "";
      }
    }

    data.supportedClaims = callback.supportedClaims;

        cardstoreDebug("new card: tokenServiceList:" + callback.tokenServiceList);
  data.tokenServiceList = callback.tokenServiceList;

  data.stsCert = callback.stsCert;
  if (callback.requireAppliesTo) {
    data.requireAppliesTo = true;
  }
  if (callback.requireStrongRecipientIdentity) {
    data.requireStrongRecipientIdentity = true;
  }
  
  data.supportedTokenTypeList = callback.supportedTokenTypeList;

    card.carddata.data = data;
    cardstoreDebug("saving card: " + callback.cardName);
//  alert("importedCard="+importedCard);
//  //TODO remove return when it is working
//  return;
    return card;
}

function newSelfIssuedCard(callback) {
    card = newInfocard();
    
    card.name = callback.cardName;
    card.type = callback.type;
    if (callback["cardVersion"] == undefined) {
        card.version = 1;
    } else {
      card.version = callback["cardVersion"];
    }
    var id = Math.floor(Math.random()*100000+1);
    card.id = id;
    card.privatepersonalidentifier = OICCrypto.hex_sha1(callback.cardName + card.version + id);

    var count = 0;
    
    var supportedClaims = "";
    var claims = "";
    
    for (var claim in callback) {
      if (claim === "type") continue;
      if (claim === "cardName") continue;
      if (callback.hasOwnProperty(claim)) {
        if (callback[claim]) {
            var displayTag = callback[claim].displayTag;
            supportedClaims += "<ic:SupportedClaimType Uri=\"" + claim + "\">" + 
              "<ic:DisplayTag>" + displayTag +"</ic:DisplayTag></ic:SupportedClaimType>";
            var claimValue = callback[claim].claimValue;
          claims += "<ic:ClaimValue Uri=\"" + claim + "\"><ic:Value>" + claimValue + "</ic:Value></ic:ClaimValue>";
          count++;
        }
      }
    }

    var masterKey = "<ic:MasterKey>" + card.privatepersonalidentifier + "</ic:MasterKey>";
    
    var privateCardData;
    if (count > 0) {
      var claimValueList = "<ic:ClaimValueList>" + claims + "</ic:ClaimValueList>";
      privateCardData = "<ic:InformationCardPrivateData xmlns:ic=\"http://schemas.xmlsoap.org/ws/2005/05/identity\">"
        + masterKey
        + claimValueList + "</ic:InformationCardPrivateData>";
    } else {
      privateCardData = "<ic:InformationCardPrivateData xmlns:ic=\"http://schemas.xmlsoap.org/ws/2005/05/identity\">"
        + masterKey
        + "</ic:InformationCardPrivateData>";
    }
    
    supportedClaims += "<ic:SupportedClaimType " +
      "Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier\"/>";
    var supportedClaimTypeList = "<ic:SupportedClaimTypeList xmlns:ic=\"http://schemas.xmlsoap.org/ws/2005/05/identity\">" +
      supportedClaims + "</ic:SupportedClaimTypeList>";

    card.carddata += new XML(privateCardData);
    card.carddata += new XML(supportedClaimTypeList);
    
    return card;
}

function newOpenIdCard(callback) {
    var card = newInfocard();
    card.name = "" + callback.cardName + "";
    card.type = "" + callback.type;
    var version = "1";
    card.version = version;
    card.id = "" + callback.cardId + "";
    return card;
}

function newDB(){

    var dbFile = new XML("<infocards/>");
    dbFile.version = "1";
    return dbFile;
//cardstoreDebug("newDB start");
//  if (TokenIssuer.initialize() == true) {
//      var dbFile = TokenIssuer.newCardStore();
//      cardstoreDebug ( "New DB: " + dbFile.toString());
//      return dbFile;
//  } else {
//    cardstoreDebug("error initializing the TokenIssuer");
//    return null;
//  }
}

function cardstoreDebug(msg) {
  var debug = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
  debug.logStringMessage("cardstore: " + msg);
}

