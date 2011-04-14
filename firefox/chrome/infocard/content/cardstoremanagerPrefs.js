const Ci = Components.interfaces;

var OICCardstoreManager = {
  log : function(msg) {
    var debug = Components.classes['@mozilla.org/consoleservice;1'].getService(Components.interfaces.nsIConsoleService);
    debug.logStringMessage("OICCardstoreManager prefs: " + msg);
  },
  
  filePicker : function() {
    var nsIFilePicker = Components.interfaces.nsIFilePicker;
    var fp = Components.classes["@mozilla.org/filepicker;1"].createInstance(nsIFilePicker);
    fp.init(window, "Select a File", nsIFilePicker.modeOpen);
    fp.appendFilters( nsIFilePicker.filterAll );
    var res = fp.show();
    if (res == nsIFilePicker.returnOK) {
      var textbox = document.getElementById("cardStoreLocalFilePath");
      textbox.value = fp.file.path;
    }

  },

  doLoad : function() {
    OICCardstoreManager.log("doLoad start");
  },

  doUnload : function() {
    OICCardstoreManager.log("doUnload start");
  },

  addCardstoreToTree : function(cardstore, slots)
  {
    OICCardstoreManager.log("addCardstoreToTree: start cardstore=" + cardstore);
    try {
      var tree = document.getElementById("cardstore_list");
      var item  = document.createElement("treeitem");
      var row  = document.createElement("treerow");
      var cell = document.createElement("treecell");
      cell.setAttribute("label", cardstore);
      row.appendChild(cell);
      item.appendChild(row);
      var parent = document.createElement("treechildren");
      for (var i = 0; i<slots.length; i++) {
        var child_item = document.createElement("treeitem");
        var child_row = document.createElement("treerow");
        var child_cell = document.createElement("treecell");
        child_cell.setAttribute("label", slots[i]);
        child_row.appendChild(child_cell);
        child_item.appendChild(child_row);
        child_item.setAttribute("pk11kind", "slot");
        parent.appendChild(child_item);
      }
      item.appendChild(parent);
      item.setAttribute("pk11kind", "cardstore");
      item.setAttribute("open", "true");
      item.setAttribute("container", "true");
      tree.appendChild(item);
    } catch(e) {
      OICCardstoreManager.log("addCardstoreToTree: Exception: " + e);
      throw e;
    }
  },

  onSmartCardChange : function() {
    OICCardstoreManager.log("onSmartCardChange start");
  },

  LoadCardstores : function() {
    OICCardstoreManager.log("LoadCardstores start");
    
    var bundle = srGetStrBundle("chrome://infocard/locale/cardstoremanager.properties");

    window.crypto.enableSmartCardEvents = true;
    document.addEventListener("smartcard-insert", OICCardstoreManager.onSmartCardChange, false);
    document.addEventListener("smartcard-remove", OICCardstoreManager.onSmartCardChange, false);

    var cardstoreManagerSvc = Components.classes["@openinfocard.org/CardstoreManager/service;1"]
    .getService(Ci.IInformationCardStoreManager);

    var cardstores = cardstoreManagerSvc.getCardstores();
    cardstores.QueryInterface(Ci.nsISimpleEnumerator);
    while (cardstores.hasMoreElements()) {
      var cardstore = cardstores.getNext();
      cardstore.QueryInterface(Ci.IInformationCardStore);
      var name = cardstore.getCardStoreName();
      OICCardstoreManager.log("LoadCardstores Name=" + name);
      OICCardstoreManager.addCardstoreToTree(name, ["foo", "bar"]);
    }

  }    
};
