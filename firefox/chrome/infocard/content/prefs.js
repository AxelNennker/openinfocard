const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;
const Cu = Components.utils;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Components.utils.import("resource://infocard/IdentitySelectorDiag.jsm");

function prefsDebug(msg) {
  var debug = Components.classes['@mozilla.org/consoleservice;1'].getService(Components.interfaces.nsIConsoleService);
  debug.logStringMessage("openinfocard prefs: " + msg);
}

function prefsCallback() {
  var mgmtWindow = window.openDialog("chrome://infocard/content/cardManager.xul","InfoCard Selector", "modal,chrome,resizable,width=800,height=640,centerscreen");
}

function filePicker() {

  var nsIFilePicker = Components.interfaces.nsIFilePicker;
  var fp = Components.classes["@mozilla.org/filepicker;1"].createInstance(nsIFilePicker);
  fp.init(window, "Select a File", nsIFilePicker.modeOpen);
  fp.appendFilters( nsIFilePicker.filterAll );
  var res = fp.show();
  if (res == nsIFilePicker.returnOK) {
    var textbox = document.getElementById("cardStoreLocalFilePath");
    textbox.value = fp.file.path;
    var pref = document.getElementById("pref_cardStoreLocalFilePath");
    pref.value = fp.file.path;
  }

}

function populateMenu() {
  var cid = null;

  // lookup class id from config.
  var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);
  var pbi = prefs.QueryInterface(Components.interfaces.nsIPrefBranch);

  cid = pbi.getCharPref("extensions.identityselector.selector_class");

  prefsDebug("selected selector " + cid);
  var menuList = document.getElementById("selector");
  var menuPopup = document.getElementById("menupopup");

  var catman = XPCOMUtils.categoryManager;

  var count = 0;
  var menuitem = null;
  var cardstores = catman.enumerateCategory ( "information-card-storage" );
  while (cardstores.hasMoreElements()) {
    try {
      var item = cardstores.getNext();
      var entry = item.QueryInterface(Ci.nsISupportsCString);
      if (!entry || (entry == "")) {
        continue; // can this happen?
      }
      var clasz = Cc[entry];
      var cardstoreService = clasz.getService(Ci.IInformationCardStore);
  
      prefsDebug("contractid=" + entry);
      
      var cardstoreName = cardstoreService.getCardStoreName();
      menuitem = document.createElement("menuitem");
      menuitem.setAttribute("label", cardstoreName);
      menuitem.setAttribute("value", entry);
      menuPopup.appendChild(menuitem);
      count++;
      if (!cid || (cid == "")) {
        pbi.setCharPref("extensions.identityselector.selector_class", entry);
        cid = entry;
      }
      if (entry == cid) {
        prefsDebug("selecting " + cardstoreName);
        menuList.selectedItem = menuitem;
      }
    } catch (ee) {
      IdentitySelectorDiag.reportError("populate menu", "" + ee);
    }
  }
  if ((count === 1) && (menuitem)){
    menuList.selectedItem = menuitem;
  }

}
