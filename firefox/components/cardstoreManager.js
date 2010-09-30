
const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

function debug(msg) {
  var consoleService = Cc[ "@mozilla.org/consoleservice;1"].getService(Ci.nsIConsoleService);
  consoleService.logStringMessage("CardstoreManagerService: " + msg);
}

Cu.import("resource://gre/modules/XPCOMUtils.jsm");

function CardstoreEnumerator() {
  var categoryManager = XPCOMUtils.categoryManager;
  this.enumerator = categoryManager.enumerateCategory("information-card-storage");
}

CardstoreEnumerator.prototype.QueryInterface = function(iid) {
  if (iid.equals(Components.interfaces.nsISupports) ||
      iid.equals(Components.interfaces.nsISimpleEnumerator))
    return this;
  throw Components.results.NS_NOINTERFACE;
};

CardstoreEnumerator.prototype.getNext = function() {
  var item = this.enumerator.getNext();
  var entry = item.QueryInterface(Ci.nsISupportsCString)
  var clasz = Cc[entry];
  var cardstoreService = clasz.getService(Ci.IInformationCardStore);
  return cardstoreService;
};

CardstoreEnumerator.prototype.hasMoreElements = function() {
  return this.enumerator.hasMoreElements();
};

function CardstoreManagerService() {
  this.wrappedJSObject = this; // no interface definition. callable only from
                                // javascript
}

CardstoreManagerService.prototype = {
  classDescription: "CardstoreManager Service",
  contractID: "@openinfocard.org/CardstoreManager/service;1",
  classID: Components.ID("{74b89fb0-cafe-4ae8-a3ec-dd164117f6de}"),
  service : true,
  QueryInterface: XPCOMUtils.generateQI([Ci.IInformationCardStoreManager,
                                         Ci.nsISupports]),

  getCardstores : function() {
    return new CardstoreEnumerator();
  },

};

/**
* XPCOMUtils.generateNSGetFactory was introduced in Mozilla 2 (Firefox 4).
* XPCOMUtils.generateNSGetModule is for Mozilla 1.9.2 (Firefox 3.6).
*/
if (XPCOMUtils.generateNSGetFactory) {
  var NSGetFactory = XPCOMUtils.generateNSGetFactory([CardstoreManagerService]);
} else {
  var NSGetModule = XPCOMUtils.generateNSGetModule([CardstoreManagerService]);
}
