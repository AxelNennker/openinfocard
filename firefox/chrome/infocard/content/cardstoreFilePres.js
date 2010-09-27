
var OICCardstoreFile = {
  log : function(msg) {
  var debug = Components.classes['@mozilla.org/consoleservice;1'].getService(Components.interfaces.nsIConsoleService);
  debug.logStringMessage("OICCardstoreFile prefs: " + msg);
  },
  
  filePicker : function() {
    netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
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

  cardstoreFileOnload : function() {
    OICCardstoreFile.log("onload start");
    if (window && ("arguments" in window)) {
      var args = window.arguments;
      if (args.cardStoreLocalFilePath) {
        var elt = document.getElemenetById("cardStoreLocalFilePath");
        if (elt) {
          elt.value = args.cardStoreLocalFilePath;
        }
      }
      if (args.cardStoreLocalFileName) {
        var elt = document.getElemenetById("cardStoreLocalFileName");
        if (elt) {
          elt.value = args.cardStoreLocalFileName;
        }
      }
    }
  }    
};
