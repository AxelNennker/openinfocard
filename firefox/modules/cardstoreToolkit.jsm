var EXPORTED_SYMBOLS = ["CardstoreToolkit"];  

var CardstoreToolkit = {
  readCardStore : function readCardStore() {
    var cardstoreManagerSvc = Components.classes["@openinfocard.org/CardstoreManager/service;1"]
        .getService(Components.interfaces.nsIHelloWorld);

    var cardFile = cardstoreManagerSvc.wrappedJSObject.readCardStore();
    return cardFile;
  }
};
