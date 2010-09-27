
const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

function debug(msg) {
  var consoleService = Cc[ "@mozilla.org/consoleservice;1"].getService(Ci.nsIConsoleService);
  consoleService.logStringMessage("CardstoreManagerService: " + msg);
}

Cu.import("resource://gre/modules/XPCOMUtils.jsm");

function CardstoreManagerService() {
  this.wrappedJSObject = this; // no interface definition. callable only from
                                // javascript
}
CardstoreManagerService.prototype = {
  classDescription: "CardstoreManager Service",
  contractID: "@openinfocard.org/CardstoreManager/service;1",
  classID: Components.ID("{74b89fb0-cafe-4ae8-a3ec-dd164117f6de}"),
  _xpcom_categories: [{ category: "app-startup", service: true },
                      { category: "profile-after-change", service: true }],

  mCardstores: [],
  
  QueryInterface: XPCOMUtils.generateQI([Ci.nsIHelloWorld, 
                                         Ci.nsIObserver,
                                         Ci.nsISupportsWeakReference]),

  observe: function CMS__observe(subject, topic, data) {
    var consoleService = Cc[ "@mozilla.org/consoleservice;1"].getService(Ci.nsIConsoleService);
    try {
        switch (topic) {
        case "app-startup": // fall through
        case "profile-after-change":
          consoleService.logStringMessage("CardstoreManagerService: profile-after-change");
          let os = Cc["@mozilla.org/observer-service;1"].
            getService(Ci.nsIObserverService);
          os.addObserver(this, "final-ui-startup", true);
          var categoryManager = XPCOMUtils.categoryManager;
          var enumerator = categoryManager.enumerateCategory("information-card-storage");
          while (enumerator.hasMoreElements()) {
            var item = enumerator.getNext();
            var entry = item.QueryInterface(Ci.nsISupportsCString)
            consoleService.logStringMessage("CardstoreManagerService: entry=" + entry);
            var clasz = Cc[entry];
            if (clasz) {
              var cardstoreService = clasz.getService(Components.interfaces.IInformationCardStore);
              var cardstorename = cardstoreService.getCardStoreName();
              consoleService.logStringMessage("CardstoreManagerService: cardstorename=" + cardstorename);
              this.mCardstores.push(cardstoreService);
            } else {
              consoleService.logStringMessage("CardstoreManagerService: Components.classes[" + entry + "] is undefined or null");
            }
          }
          consoleService.logStringMessage("CardstoreManagerService: lenght=" + this.mCardstores.length);
          break;
    
        case "final-ui-startup":
          consoleService.logStringMessage("CardstoreManagerService: final-ui-startup");
          // TODO read cardstore and cache it
          break;
        }
    } catch (e) {
      consoleService.logStringMessage("CardstoreManagerService: exception=" + e);
      dump("CardstoreManagerService Exception:" + e);
    }
  }, 
  
  readCardStore : function readCardStore() {
    var cardstore = this.mCardstores[0];
    return cardstore.readCardStore();
  }
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
