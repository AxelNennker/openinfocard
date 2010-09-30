var EXPORTED_SYMBOLS = ["CardstoreToolkit"];  

const Ci = Components.interfaces;

var CardstoreToolkit = {
  readCardStore : function readCardStore() {
    var cardstoreManagerSvc = Components.classes["@openinfocard.org/CardstoreManager/service;1"]
        .getService(Ci.IInformationCardStoreManager);

    var cardstores = cardstoreManagerSvc.getCardstores();
    cardstores.QueryInterface(Ci.nsISimpleEnumerator);
    while (cardstores.hasMoreElements()) {
      var cardstore = cardstores.getNext();
      cardstore.QueryInterface(Ci.IInformationCardStore);
      var cardFile = cardstore.readCardStore(); // FIXME merge cardstores
      return cardFile;
    }
  }
};
