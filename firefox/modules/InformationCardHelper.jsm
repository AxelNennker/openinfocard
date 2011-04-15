var EXPORTED_SYMBOLS = ["InformationCardHelper"]; 

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;
const Cu = Components.utils;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://infocard/IdentitySelectorDiag.jsm");
Cu.import("resource://infocard/IdentitySelectorPrefs.jsm");

var InformationCardHelper = {
  alert : function _alert(msg) {
    var data = {};
    data.msg = msg;
    var ww = Components.classes["@mozilla.org/embedcomp/window-watcher;1"]
                       .getService(Components.interfaces.nsIWindowWatcher);
    ww.openWindow(null, "chrome://infocard/content/alert.xul",
      "Openinfocard", "chrome,centerscreen", data);
  },
  
  isSslCertEV : function _isSslCertEV(doc) {
    var browser = doc.defaultView.getBrowser();
    if (browser !== null) {
      if (browser.securityUI !== undefined) {
         var secureUi = browser.securityUI;
         return (secureUi.state & Components.interfaces.nsIWebProgressListener.STATE_IDENTITY_EV_TOPLEVEL);
      }
    }
    return false;
  },
  
  getBrowserForUrl : function _getBrowserForUrl(url) {
      IdentitySelectorDiag.logMessage("InformationCardHelper.getBrowserForUrl", "url=" + url);
      var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"]
                         .getService(Components.interfaces.nsIWindowMediator);
      var browserEnumerator = wm.getEnumerator("navigator:browser");
    
      // Check each browser instance for our URL
      while (browserEnumerator.hasMoreElements()) {
        var browserWin = browserEnumerator.getNext();
        var tabbrowser = browserWin.gBrowser;
    
        // Check each tab of this browser instance
        var numTabs = tabbrowser.browsers.length;
        for (var index = 0; index < numTabs; index++) {
          var currentBrowser = tabbrowser.getBrowserAtIndex(index);
          if (url == currentBrowser.currentURI.spec) {
            return currentBrowser;
          }
        }
      }
      return null;
  },
  
  getBrowserForDoc : function _getBrowserForDoc(doc) {
    IdentitySelectorDiag.logMessage("InformationCardHelper.getBrowserForDoc", "doc.location.href=" + doc.location.href);
    var browser = null;
    
    var aContent = doc.getElementById( "content");
    if (aContent) {
      browser = aContent.mCurrentBrowser;
      return browser;
    }

    if (doc.defaultView) {
      IdentitySelectorDiag.logMessage("InformationCardHelper.getBrowserForDoc", "defaultView");
      doc.defaultView
    }
    
    var url = doc.location.href;
    browser = InformationCardHelper.getBrowserForUrl(url);
    
    return browser;
  },
  
  getSSLCertFromDocument : function _getSSLCertFromDocument(doc) {
    var browser = InformationCardHelper.getBrowserForDoc(doc);
    return InformationCardHelper.getSSLCertFromBrowser(browser);
  },
  
  getSSLCertFromBrowser : function _getSSLCertFromBrowser(browser) {
    var sslCert = null;

    if (browser.securityUI) {
      var secureUi = browser.securityUI;
      var sslStatusProvider = secureUi.QueryInterface(Components.interfaces.nsISSLStatusProvider);
      if((sslStatusProvider) && (sslStatusProvider.SSLStatus)) {
         try {
            var sslStatus = sslStatusProvider.SSLStatus.QueryInterface(Components.interfaces.nsISSLStatus);
            if( (sslStatus) && (sslStatus.serverCert)) {
               sslCert = sslStatus.serverCert;
            }
         }
         catch( e) {
            IdentitySelectorDiag.logMessage("InformationCardHelper.getSSLCertFromDocument", "getSSLCertFromDocument: " + e);
         }
      }
    } else {
      IdentitySelectorDiag.logMessage("InformationCardHelper.getSSLCertFromDocument", "browser.securityUI === undefined");
      IdentitySelectorDiag.logMessage("InformationCardHelper.getSSLCertFromDocument", "browser.currentURI="+browser.currentURI);
    }
    return sslCert;
  },
  
  parseRpPolicy: function _parseRpPolicy(icLoginPolicy) {
        // IdentitySelectorDiag.logMessage("parseRpPolicy",
        // "typeof(icLoginPolicy)=" +
        // typeof(icLoginPolicy)); // xml
        IdentitySelectorDiag.logMessage("parseRpPolicy", "icLoginPolicy=" + icLoginPolicy.toString());
        var data = {};
        // if( icLoginPolicy.wrappedJSObject)
        // {
        // IdentitySelectorDiag.logMessage("parseRpPolicy", "icLoginPolicy =" +
        // icLoginPolicy.wrappedJSObject.toString());
        // icLoginPolicy = icLoginPolicy.wrappedJSObject;
        // }
        // var xmlPolicy = new XML(icLoginPolicy.toString());
        // IdentitySelectorDiag.logMessage("parseRpPolicy",
        // "xmlPolicy.child(1).@name=" +
        // xmlPolicy.child(1).@name.toString());
        var params = icLoginPolicy.toString().split("<param");
        IdentitySelectorDiag.logMessage("parseRpPolicy", "params.length=" + params.length);
        for (var i = 0; i < params.length; i++) {
            var name = null;
            var value = null;
            var param = params[i];
            IdentitySelectorDiag.logMessage("parseRpPolicy", "param i=" + i + " param=" + param);
            var j = param.indexOf('name="');
            if (j != -1) {
                var s1 = param.substring(j + 6);
                j = s1.indexOf('"');
                if (j != -1) {
                    name = s1.substring(0, j);
                    s1 = param.substring(j);
                    j = s1.indexOf("value=\"");
                    if (j != -1) {
                        s1 = s1.substring(j + 7);
                        j = s1.indexOf('"');
                        if (j != -1) {
                            value = s1.substring(0, j);
                        }
                        else {
                            IdentitySelectorDiag.logMessage("parseRpPolicy", "no closing \" in value= in " + param);
                        }
                    }
                    else {
                        IdentitySelectorDiag.logMessage("parseRpPolicy", "no value=\" in " + param);
                    }
                }
                else {
                    IdentitySelectorDiag.logMessage("parseRpPolicy", "no closing \" in name= in " + param);
                }
            }
            else {
                IdentitySelectorDiag.logMessage("parseRpPolicy", "no name= in " + param);
            }
            if ((name) && ("" + name !== "") && (value)) {
                data[name] = value;
                IdentitySelectorDiag.logMessage("parseRpPolicy", "data[" + name + "] =" + value);
            }
            else {
                IdentitySelectorDiag.logMessage("parseRpPolicy", "no name or no value in " + param);
            }
        }
        return data;
  },
    
  getCidFromPrefs: function _getCidFromPrefs() {
        var cid = null;
        // lookup class id from config.
        var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);
        var pbi = prefs.QueryInterface(Components.interfaces.nsIPrefBranch);
        cid = pbi.getCharPref("identityselector.contractid");
        return cid;
  },
  
  getObjectForClassId: function _getObjectForClassId(cid) {
        var obj = null;
        try {
            var cidClass = Components.classes[cid];
            if (cidClass) {
                obj = cidClass.createInstance();
                obj = obj.QueryInterface(Components.interfaces.IIdentitySelector);
            }
            else {
                IdentitySelectorDiag.reportError("getObjectForClassId", "the class " + cid + " is not installed");
            }
        }
        catch(e) {
            IdentitySelectorDiag.throwError("getObjectForClassId:", e);
        }
        return obj;
  },

  prepareDataForCallIdentitySelector: function _prepareDataForCallIdentitySelector(doc) {
      var data;
      var icLoginPolicy = doc.__identityselector__.icLoginPolicy;
      if (icLoginPolicy !== undefined) {
        IdentitySelectorDiag.logMessage("IdentitySelector.callIdentitySelector", "icLoginPolicy=" + icLoginPolicy);
        var sameSchemeAndDomain = InformationCardHelper.sameSchemeAndDomain(doc, doc.location.href);
        if (sameSchemeAndDomain === false) {
          Components.utils.reportError("IdentitySelector.callIdentitySelector: Ignoring: sameSchemeAndDomain === false");
        }
        data = InformationCardHelper.parseRpPolicy(icLoginPolicy);
      } else {
        IdentitySelectorDiag.logMessage("IdentitySelector.callIdentitySelector", "icLoginPolicy=undefined");
      }
      
      if (data) {
        if  (!data.hasOwnProperty("openidReturnToUri")) {
          if (doc.__identityselector__.openidReturnToUri) {
            data.openidReturnToUri = doc.__identityselector__.openidReturnToUri;
          }
        }
      } else {
        data = {};
        if (doc.__identityselector__.openidReturnToUri) {
          data.openidReturnToUri = doc.__identityselector__.openidReturnToUri;
        }
      }
      
      if (!icLoginPolicy && data.openidReturnToUri && !data.tokenType) {
        data.tokenType = "http://specs.openid.net/auth/2.0";
      }
      
      if (doc.__identityselector__.cardId) {
          data.cardid = "" + doc.__identityselector__.cardId;
          IdentitySelectorDiag.logMessage("IdentitySelector.callIdentitySelector", "cardid=" + data.cardid);
      }
      data.recipient = doc.location.href;
      
      if (doc.__identityselector__.sslMode) {
          data.sslMode = "" + doc.__identityselector__.sslMode;
      }
      return data;
  },

  callIdentitySelector: function _callIdentitySelector(browser, doc) {
    IdentitySelectorDiag.logMessage("IdentitySelector.callIdentitySelector", "doc.location.href=" + doc.location.href);

    var aSelectorClasz = InformationCardHelper.getCardstore();
    if (!aSelectorClasz) {
      IdentitySelectorDiag.reportError( "onCallIdentitySelector",
                "Unable to locate an identity selector.  " +
                "Please make sure one is installed.");
      return null;
    }
    var dataObj = InformationCardHelper.prepareDataForCallIdentitySelector(doc);

    var sslCert = InformationCardHelper.getSSLCertFromBrowser(browser);
    
    var extraParams = function(){
      var extraParams = [];
      var len = 0;
      for (var i in dataObj) {
        if (dataObj.hasOwnProperty(i)) {
          IdentitySelectorDiag.logMessage("onCallIdentitySelector ", 
              "data[" + i + "]=" + dataObj[i]); 
          if (("issuer" !== ""+i) 
            && ("recipient" !== ""+i)
            && ("requiredClaims" !== ""+i)
            && ("optionalClaims" !== ""+i)
            && ("tokenType" !== ""+i)
            && ("privacyUrl" !== ""+i)
            && ("privacyVersion" !== ""+i)
            && ("issuerPolicy" !== ""+i)) 
          {
            var obj = {};
            obj[i] = dataObj[i];
            len = extraParams.length;
            extraParams[len] = JSON.stringify(obj);
            IdentitySelectorDiag.logMessage("onCallIdentitySelector ",
                "extraParams[" + len + "] = " + extraParams[len]);
          } else {
            IdentitySelectorDiag.logMessage("onCallIdentitySelector ",
                "i=" + i + "; value=" + dataObj[i] + ";");
          }
        }
      }
      return extraParams;
    }();
                          
    // call identity selector
    var token = aSelectorClasz.GetBrowserToken(dataObj.issuer,
                              dataObj.recipient, dataObj.requiredClaims,
                              dataObj.optionalClaims, dataObj.tokenType, dataObj.privacyUrl,
                              dataObj.privacyVersion, sslCert, dataObj.issuerPolicy,
                              extraParams.length, extraParams);

    if (token) {
      var icLoginService = doc.__identityselector__.icLoginService;
      
      IdentitySelectorDiag.logMessage("IdentitySelector.callIdentitySelector", "sending token " + token + " to " + icLoginService);
      var req = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
      req.open('POST', icLoginService, false);
      req.setRequestHeader("Content-Length", token.length);
      try {
          req.send(token);
      } catch(e) {
       IdentitySelectorDiag.reportError("InformationCardHelper.callIdentitySelector", "Exception: " + e);
       InformationCardHelper.alert("posting the security token to " + icLoginService + " failed" + e);
       return;
      }
      IdentitySelectorDiag.logMessage("IdentitySelector.callIdentitySelector status=" + req.status);
      if (req.status == 200) {
          doc.location.href = icLoginService;
          return;
          // fine
      } else {
       IdentitySelectorDiag.reportError("InformationCardHelper.callIdentitySelector", 
        "The service " + icLoginService + " returned an error:\n" + req.responseText);
       InformationCardHelper.alert("The service " + icLoginService + " returned an error:\n" + req.responseText);
       return;
      }
    } else {
        IdentitySelectorDiag.logMessage("IdentitySelector.callIdentitySelector", 
            "token == null for doc.location.href=" + doc.location.href);
    }

  },

  // ***********************************************************************
  // Method: findRelatedObject
  // loop through the objects in the doc to find the one that has targetId
  // as the value of icDropTargetId
  // ***********************************************************************
  findRelatedObject: function _findRelatedObject(doc, targetId) {
    var objElem;
    var objTypeStr;
    var itemCount = 0;
    // Process all of the information card objects in the document
    var objElems = doc.getElementsByTagName("OBJECT");
    for (var i = 0; i < objElems.length; i++) {
        objElem = objElems[i];
        objTypeStr = objElem.getAttribute("TYPE");
        if (objTypeStr === null || objTypeStr.toLowerCase() !== "application/x-informationcard") {
            continue;
        }
        itemCount++;
        if (objElem.icDropTargetId) {
            IdentitySelectorDiag.logMessage("IdentitySelector.findRelatedObject", "dropTarget for object " + ((objElem.name) ? objElem.name: "") + " is " + objElem.icDropTargetId);
            if (targetId == objElem.icDropTargetId) {
                return objElem;
            }
        }
        else {
            IdentitySelectorDiag.logMessage("IdentitySelector.findRelatedObject", "no dropTarget specified for object " + objElem.name);
        }
    }
    // if there is exactly one object then return that
    if (itemCount === 1) {
      objElem = objElems[0];
      objTypeStr = objElem.getAttribute("TYPE");
      if (objTypeStr !== null || objTypeStr.toLowerCase() === "application/x-informationcard") {
        return objElem;
      }
    }
    
    return null;
  },

  sameSchemeAndDomain: function _sameSchemeAndDomain(ownerDocument, htmlDoc) {
    var i;
    IdentitySelectorDiag.logMessage("sameSchemeAndDomain", "ownerDocument.location.href=" + ownerDocument.location.href);
    var topScheme = ownerDocument.location.protocol;
    var topDomain = ownerDocument.location.host;
    // TODO this should go up to the top. Currently this code supports only
    // only
    // level deep nesting.
    IdentitySelectorDiag.logMessage("sameSchemeAndDomain", " topURL:" + ownerDocument.location.href);
    var subWindowScheme = "";
    if (htmlDoc === undefined) {
      throw "htmlDoc === undefined. caller=" + InformationCardHelper.sameSchemeAndDomain.caller;
    }
    if (htmlDoc.location === undefined) {
        // htmlDoc is a string
        IdentitySelectorDiag.logMessage("sameSchemeAndDomain", " subWindowURL:" + htmlDoc);
        // it is a string not a doc
        i = htmlDoc.indexOf(':');
        if (i != -1) {
            subWindowScheme = htmlDoc.substring(0, i + 1);
            // include the colon
        }
    }
    else {
        IdentitySelectorDiag.logMessage("sameSchemeAndDomain", " subWindowURL:" + htmlDoc.location.href);
        subWindowScheme = htmlDoc.location.protocol;
    }
    IdentitySelectorDiag.logMessage("sameSchemeAndDomain", " subWindowScheme:" + subWindowScheme);
    if ((subWindowScheme == topScheme) || ((topScheme === "https" ) && (subWindowScheme === "http"))) {
        IdentitySelectorDiag.logMessage("sameSchemeAndDomain", " topDomain:" + topDomain);
        var subWindowDomain = "";
        if (htmlDoc.location === undefined) {
            // it is a string not a doc
            i = htmlDoc.indexOf("//");
            if (i != -1) {
                var rest = htmlDoc.substr(i + 2);
                i = rest.indexOf("/");
                if (i != -1) {
                    subWindowDomain = rest.substring(0, i);
                }
                else {
                    subWindowDomain = rest;
                }
            }
        }
        else {
            subWindowDomain = htmlDoc.location.host;
        }
        IdentitySelectorDiag.logMessage("sameSchemeAndDomain", " subWindowDomain:" + subWindowDomain);
        if (subWindowDomain == topDomain) {
            return true;
        }
        else {
            IdentitySelectorDiag.logMessage("sameSchemeAndDomain", "domains do not match. " + subWindowDomain + "!=" + topDomain);
        }
    }
    else {
        IdentitySelectorDiag.logMessage("sameSchemeAndDomain", "schemes do not match. " + subWindowScheme + "!=" + topScheme);
    }
    return false;
  },
  
  getCardstore : function _getCardstore() {
    var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);
    var pbi = prefs.QueryInterface(Components.interfaces.nsIPrefBranch);
  
    cid = pbi.getCharPref("extensions.identityselector.selector_class");
    if (cid) {
      try {
          var clasz = Cc[cid];
          if (clasz) {
            var cardstoreService = clasz.getService(Ci.IInformationCardStore);
            return cardstoreService;
          } else {
            IdentitySelectorDiag.logMessage("getCardstore", "class is not defined: " + entry);
          } 
      } catch(e) {
        IdentitySelectorDiag.logMessage("getCardstore", "Exeption: " + e);
      }
    } else {
       IdentitySelectorDiag.logMessage("getCardstore", "cid is not defined");
    }
    var catman = XPCOMUtils.categoryManager;  
    var cardstores = catman.enumerateCategory( "information-card-storage" );
    while (cardstores.hasMoreElements()) {
      try {
        var item = cardstores.getNext();
        var entry = item.QueryInterface(Ci.nsISupportsCString);
        if (!entry || (entry == "")) {
          continue; // can this happen?
        }
        var clasz = Cc[entry];
        if (clasz) {
          var cardstoreService = clasz.getService(Ci.IInformationCardStore);
          return cardstoreService;
        } else {
          IdentitySelectorDiag.logMessage("getCardstore", "class is not defined: " + entry);
        } 
      } catch (ee) {
        IdentitySelectorDiag.reportError("getCardstore", "" + ee);
      }
    }
    IdentitySelectorDiag.logMessage("getCardstore", "class is not defined: " + entry);
    return null;
  }

};