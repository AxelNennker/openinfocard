const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;
const Cu = Components.utils;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://infocard/tokenissuer.jsm");

function OicCardstorePhone() {
  // If you only need to access your component from Javascript, uncomment the following line:
  this.wrappedJSObject = this;
}

OicCardstorePhone.prototype = {
    // properties required for XPCOM registration:
    classDescription: "The openinfocard cardstore on a mobile phone implementation",
    classID:          Components.ID("{bdc78940-db54-11de-8a39-0800200c9a66}"),
    contractID:       "@openinfocard.org/cardstore-phone;1",
    _xpcom_categories: [{  
           category: "information-card-storage",
           entry: "@openinfocard.org/cardstore-phone;1",
           service: true  
    }],  
    // QueryInterface implementation
    QueryInterface: XPCOMUtils.generateQI([Ci.IInformationCardStore,
                                           Ci.nsISupports]),

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
      return null;
    },
    
    readCardStore: function readCardStore() {
      var cardFile = TokenIssuer.getAllCards();
      this.log("mWalletCardstore.readCardStore:" + cardFile);
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

var components = [OicCardstorePhone];

/**
* XPCOMUtils.generateNSGetFactory was introduced in Mozilla 2 (Firefox 4).
* XPCOMUtils.generateNSGetModule is for Mozilla 1.9.2 (Firefox 3.6).
*/
if (XPCOMUtils.generateNSGetFactory) {
  var NSGetFactory = XPCOMUtils.generateNSGetFactory([OicCardstorePhone]);
} else {
  var NSGetModule = XPCOMUtils.generateNSGetModule([OicCardstorePhone]);
}


