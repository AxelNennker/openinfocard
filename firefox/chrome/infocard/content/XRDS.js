Components.utils.import("resource://infocard/IdentitySelectorDiag.jsm");
Components.utils.import("resource://infocard/InformationCardHelper.jsm");
Components.utils.import("resource://infocard/InformationCardDragAndDrop.jsm");

var gObj = null;

var IcXrdsRetrieveX = {
  retrieveX : function(doc, hrefStr, listenerO) {
    try {
      IdentitySelectorDiag.logMessage("IcXrdsRetrieveX::retrieveX: start href=", hrefStr);
       if (typeof(hrefStr) == 'string') {
          var i = hrefStr.indexOf("://");
          if (i == - 1) {
             // it is not an URL. Try to build an URL from the baseURI of the
             // document.
             var baseUri = doc.baseURI;
             if ((baseUri !== null) && (baseUri.length > 0)) {
                if ((baseUri.length - 1) == baseUri.lastIndexOf('/')) {
                   // ends with /
                   hrefStr = baseUri + hrefStr;
                   }
                else {
                   hrefStr = baseUri + '/' + hrefStr;
                   }
                IdentitySelectorDiag.logMessage("IcXrdsRetrieveX::retrieveX: href=", hrefStr);
                }
             // else no baseUri
             }
          // else its an URL. Go ahead.
          }
       // else not string but document
       var sameSchemeAndDomain = InformationCardHelper.sameSchemeAndDomain(doc, hrefStr);
       if (sameSchemeAndDomain !== true) {
         Components.utils.reportError("IcXrdsRetrieveX: ignoring scheme resp domain mismatch");
       }
       
      var req = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
      try {
        req.open('GET', hrefStr, true);
      } catch (openException) {
        Components.utils.reportError("IcXrdsRetrieveX: failed to open " + hrefStr + "\n" + openException);
        throw openException;
      }
      req.setRequestHeader('Content-Type', 'text/xml');
      req.overrideMimeType('text/xml');
      var listener = new listenerO(doc, hrefStr);
      
      if (doc.__identityselector__.timer === undefined) {
          var event = { notify: function(timer) { InformationCardStatusbar.onProgress(doc, null); } };
          doc.__identityselector__.timerUrlArray = [];
          doc.__identityselector__.timerUrlArray[hrefStr] = true;
          doc.__identityselector__.timer = Components.classes["@mozilla.org/timer;1"].createInstance(Components.interfaces.nsITimer);
          doc.__identityselector__.timer.initWithCallback( event, 1000, Components.interfaces.nsITimer.TYPE_REPEATING_SLACK);
          IdentitySelectorDiag.logMessage("IcXrdsRetrieveX::retrieveX", "started timer: " + doc.location.href);
      } else {
        IdentitySelectorDiag.logMessage("IcXrdsRetrieveX::retrieveX", "timer already started: " + doc.location.href);
        // a statusbar time is already running. Just add the hrefStr to the list of outstanding requests
          doc.__identityselector__.timerUrlArray[doc.__identityselector__.timerUrlArray.length] = hrefStr;
      }
      
//            var timeoutId = doc.defaultView.setInterval(function(){InformationCardStatusbar.onProgress(doc, null);}, 500, true);
//            var timeoutId = window.setInterval(function(){InformationCardStatusbar.onProgress(doc, null);}, 1000, true);
//            if ((InformationCardStatusbar !== undefined) &&(typeof(InformationCardStatusbar.onProgress) === "function")) {
//              req.onprogress = function(aEvent) {
//                IdentitySelectorDiag.logMessage("IcXrdsRetrieveX::retrieveX", " onprogress");
//                InformationCardStatusbar.onProgress(doc, aEvent);
//              };
//            } else {
//              IdentitySelectorDiag.logMessage("IcXrdsRetrieveX::retrieveX", " InformationCardStatusbar is undefined: " + doc.location.href);
//            }
      req.onreadystatechange = function (aEvent) {
         if (req.readyState == 4) {
          IdentitySelectorDiag.logMessage("IcXrdsRetrieveX::retrieveX onreadystatechange", "status=" + req.status + " deleting timer: " + hrefStr);
          delete doc.__identityselector__.timerUrlArray[hrefStr];
          if (doc.__identityselector__.timerUrlArray.length === 0) {
            InformationCardStatusbar.cancelTimer(doc);
          }
            if (!req.responseXML) {
               listener.onError(req.responseText);
               return;
               }
            if (req.status != 200) {
               listener.onError(req.statusText);
               return;
               }
            listener.onReady(req.responseXML);
            }
         };
      req.send(null);
    } catch(e) {
       IdentitySelectorDiag.logMessage("IcXrdsRetrieveX::retrieveXrds: ", e);
       throw e;
    }
  }
  
};

var IcXrdsComponent = {
  logMessage : function(location, msg) {
    Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService).logStringMessage( "IcXrdsComponent:" + location + ": " + msg);
  },

  handlePolicyEvent : function(event) {
    var doc = event.target;
    var serviceType = "http://infocardfoundation.org/policy/1.0/login";
    var xrdsStr = gObj.getXrdsForSite(doc.location.href, serviceType);
    IcXrdsComponent.logMessage( "handlePolicyEvent", "type=" + serviceType + " doc.location.href="+doc.location.href + " xrds=" + xrdsStr);
      var parser = Components.classes["@mozilla.org/xmlextras/domparser;1"]
                                    .createInstance(Components.interfaces.nsIDOMParser);
    var serviceDoc = parser.parseFromString(xrdsStr, "text/xml");
    IcXrdsComponent.handlePolicy(serviceDoc, doc);
    
//    const CONTRACT_ID = "@openinfocard.org/xrds;1";
//    var doc = event.target;
//    var root = doc.documentElement;
//    var serviceType = "http://infocardfoundation.org/policy/1.0/login";
//    var tagName = "xrdsService";
//    var elements = root.getElementsByTagNameNS("urn:firefox:xrds:component", tagName);
//    if (elements.length > 0) {
//      for (var i=0; i<elements.length; i++) {
//        var href = elements[i].getAttribute("href");
//        if (href !== null && href === "serviceType") {
//          IcXrdsComponent.logMessage( "handlePolicyEvent", "i=" + i + " type=" + serviceType + " found. doc.location.href="+doc.location.href);
//          IcXrdsComponent.handlePolicy(elements[i], doc);
//        }
//      }
//    } else {
//      IcXrdsComponent.logMessage( "handlePolicyEvent", "type=" + serviceType + " not found. doc.location.href="+doc.location.href);
//    }
  },

  // boolean handle(in nsIDOMElement service, in nsIDOMDocument doc)
  // see xrds_pageinfo.idl
  handlePolicy : function(service, doc) {
        if( doc.wrappedJSObject)
        {
                doc = doc.wrappedJSObject;
        }
    this.logMessage("IcXrdsComponent:handlePolicy", doc.__identityselector__);
    if (doc.__identityselector__ === undefined) {
      IdentitySelector.runInterceptScript(doc);
    }
    if (doc.__identityselector__ !== undefined) {
      var uri = "" + service.getElementsByTagNameNS(InformationCardXrds.xrdNamespaceUriStr, "URI")[0].firstChild.nodeValue;
      doc.__identityselector__.icLoginPolicyUri = uri;
      this.logMessage("IcXrdsComponent:handlePolicy", "IC Login Service Policy: " + doc.__identityselector__.icLoginPolicyUri);
      IcXrdsComponent.retrieveIcLoginServicePolicy(doc, doc.__identityselector__.icLoginPolicyUri);
    } else {
      IcXrdsComponent.logMessage( "handlePolicy", "doc.location.href="+doc.location.href);
    }
  },
  
  handleLoginEvent : function(event) {
    var doc = event.target;
    var serviceType = "http://infocardfoundation.org/service/1.0/login";
    var xrdsStr = gObj.getXrdsForSite(doc.location.href, serviceType);
    IcXrdsComponent.logMessage( "handleLoginEvent", "type=" + serviceType + " doc.location.href="+doc.location.href + " xrds=" + xrdsStr);
      var parser = Components.classes["@mozilla.org/xmlextras/domparser;1"]
                                    .createInstance(Components.interfaces.nsIDOMParser);
    var serviceDoc = parser.parseFromString(xrdsStr, "text/xml");
    IcXrdsComponent.handleLogin(serviceDoc, doc);

//    const CONTRACT_ID = "@openinfocard.org/xrds;1";
//    var doc = event.target;
//    var root = doc.documentElement;
//    var serviceType = "http://infocardfoundation.org/service/1.0/login";
//    var tagName = "xrdsService";
//    var elements = root.getElementsByTagNameNS("urn:firefox:xrds:component", tagName);
//    if (elements.length > 0) {
//      for (var i=0; i<elements.length; i++) {
//        var href = elements[i].getAttribute("href");
//        if (href !== null && href === "serviceType") {
//          IcXrdsComponent.logMessage( "handleLoginEvent", "i=" + i + " type=" + serviceType + " found. doc.location.href="+doc.location.href);
//          IcXrdsComponent.handleLogin(elements[i], doc);
//        }
//      }
//    } else {
//      IcXrdsComponent.logMessage( "handleLoginEvent", "type=" + serviceType + " not found. doc.location.href="+doc.location.href);
//    }
  },

  handleLogin : function(service, doc) {
        if( doc.wrappedJSObject)
        {
                doc = doc.wrappedJSObject;
        }
    this.logMessage("IcXrdsComponent:handleLogin", doc.__identityselector__);
    if (doc.__identityselector__ === undefined) {
      IdentitySelector.runInterceptScript(doc);
    }
    if (doc.__identityselector__ !== undefined) {
      var uri = "" + service.getElementsByTagNameNS(InformationCardXrds.xrdNamespaceUriStr, "URI")[0].firstChild.nodeValue;
      doc.__identityselector__.icLoginService = uri;
      this.logMessage("IcXrdsComponent:handleLogin", 
          "IC Login Service: " + doc.__identityselector__.icLoginService +
          "\ndoc.location.href="+doc.location.href);
    } else {
      Components.utils.reportError( "IcXrdsComponent.handleLogin doc.__identityselector__ === undefined for " + 
          "doc.location.href="+doc.location.href);
    }
  },

  handleOpenId2ReturnTo : function(service, doc) {
    if (doc.wrappedJSObject) {
      doc = doc.wrappedJSObject;
    }
    this.logMessage("IcXrdsComponent:handleOpenId2ReturnTo", doc.__identityselector__);
    if (doc.__identityselector__ === undefined) {
      IdentitySelector.runInterceptScript(doc);
    }
    if (doc.__identityselector__ !== undefined) {
      var uri = ""
          + service.getElementsByTagNameNS(InformationCardXrds.xrdNamespaceUriStr, "URI")[0].firstChild.nodeValue;
      doc.__identityselector__.openidReturnToUri = uri;
      this.logMessage("IcXrdsComponent:handleOpenId2ReturnTo", "openid return_to uri: "
          + doc.__identityselector__.openidReturnToUri + "\ndoc.location.href=" + doc.location.href);
      if (InformationCardStatusbar !== undefined) {
        InformationCardStatusbar.showStatusbarIcon(document, true, true);
      }
      if (InformationCardUrlbar !== undefined) {
        InformationCardUrlbar.showUrlbarIcon(document, true, true);
      }
    } else {
      Components.utils.reportError("IcXrdsComponent.handleOpenId2ReturnTo doc.__identityselector__ === undefined for "
          + "doc.location.href=" + doc.location.href);
    }
  },

  /***************************************************************************
   * Desc:
    ***********************************************************************/
  icLoginServiceListener : function(doc, hrefStr) {
     this.doc = doc;
     this.hrefStr = hrefStr;
     this.onError = function(error) {
        IdentitySelectorDiag.logMessage("IcXrdsComponent::icLoginServiceListener:onError", "error=" + error);
        };
     this.onReady = function(xrds) {
        try {
           var response = new XML(Components.classes['@mozilla.org/xmlextras/xmlserializer;1'].createInstance(Components.interfaces.nsIDOMSerializer).serializeToString(xrds.documentElement));
           doc.__identityselector__.icLoginPolicy = response.toXMLString();
           IdentitySelectorDiag.logMessage("IcXrdsComponent::icLoginServiceListener:onReady", 
               "response=" + response +
               "\ndoc.location.href=" + doc.location.href);
           if ((doc.defaultView !== undefined) && (doc.defaultView)) {
               var docWindow = doc.defaultView;
               docWindow.addEventListener("dragdrop", InformationCardDragAndDrop.onWindowDragDrop, false);
               if (InformationCardStatusbar !== undefined) {
                 InformationCardStatusbar.showStatusbarIcon(document, true);
               } else {
                 IdentitySelectorDiag.logMessage("IcXrdsComponent::icLoginServiceListener:onReady", "InformationCardStatusbar===undefined");
               }
         if (InformationCardUrlbar !== undefined) {
          InformationCardUrlbar.showUrlbarIcon(document, true);
              }

              }
           }
        catch(e) {
           IdentitySelectorDiag.logMessage("IcXrdsComponent::icLoginServiceListener:onReady", "Error: " + e);
           }
        };
  },
  
  retrieveIcLoginServicePolicy : function(doc, hrefStr) {
    IcXrdsRetrieveX.retrieveX(doc, hrefStr, IcXrdsComponent.icLoginServiceListener);
    }
  
};

var oicAmcd = {
  handleHostMeta : function(hostmetaDoc) {
    var amcd = InformationCardHelper.amcd(hostmetaDoc)
  },
  
  onload : function(doc) {
    // find host-meta: http://ed.agadak.net/.well-known/host-meta
    var hostmeta = InformationCardHelper.hostmeta(doc, oicAmcd.handleHostMeta);
  }
};

var InformationCardXrds = {
  xrdNamespaceUriStr : "xri://$xrd*($v*2.0)",
  
  /***************************************************************************
   * Desc:
   **************************************************************************/
  xrdsListener: function(doc, hrefStr) {
     this.doc = doc;
     this.hrefStr = hrefStr;
     this.onError = function(error) {
        IdentitySelectorDiag.logMessage("InformationCardXrds::xrdsListener:onError", "error=" + error);
        };
     this.onReady = function(xrds) {
        try {
           var elts = xrds.getElementsByTagNameNS(InformationCardXrds.xrdNamespaceUriStr, "Service");
           IdentitySelectorDiag.logMessage("InformationCardXrds::xrdsListener:onReady", "Service elts.length="+elts.length);
           for (var i = 0; i < elts.length; i++) {
            var types = elts[i].getElementsByTagNameNS(InformationCardXrds.xrdNamespaceUriStr, "Type");
            if (types.length == 0) {
              continue;
            }
              var type = "" + types[0].firstChild.nodeValue + "";
              IdentitySelectorDiag.logMessage("InformationCardXrds::xrdsListener:onReady", "type=" + type);
              var uri;
              if (type.indexOf("http://infocardfoundation.org/policy/1.0/login") === 0) {
                IcXrdsComponent.handlePolicy(elts[i], doc);
              } else {
                 if (type.indexOf("http://infocardfoundation.org/service/1.0/login") === 0) {
                     IcXrdsComponent.handleLogin(elts[i], doc);
                 } else {
                   if (type.indexOf("http://specs.openid.net/auth/2.0/return_to") === 0) {
                       IcXrdsComponent.handleOpenId2ReturnTo(elts[i], doc);
                   } else {                    
                     IdentitySelectorDiag.logMessage("InformationCardXrds::xrdsListener:onReady", 
                        "Service: type=" + type + ":" + typeof(type) + 
                        " URI=" + 
                        elts[i].getElementsByTagNameNS(InformationCardXrds.xrdNamespaceUriStr, "URI")[0].firstChild.nodeValue);
                    }
                 }
              }
           }
//           <XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
//             <Link rel="acct-mgmt" href="http://ed.agadak.net/am/amcd"/>
//           </XRD>

           elts = xrds.getElementsByTagNameNS("http://docs.oasis-open.org/ns/xri/xrd-1.0", "Link");
           IdentitySelectorDiag.logMessage("InformationCardXrds::xrdsListener:onReady", "typeof(elts)=" + typeof(elts));
           IdentitySelectorDiag.logMessage("InformationCardXrds::xrdsListener:onReady", "Link elts.length="+elts.length);
           for (i = 0; i < elts.length; i++) {
             var linkElt = elts[i];
             IdentitySelectorDiag.logMessage("InformationCardXrds::xrdsListener:onReady", "typeof(linkElt)=" + typeof(linkElt));
             IdentitySelectorDiag.logMessage("InformationCardXrds::xrdsListener:onReady", "Link=" + linkElt);
             var rel = linkElt.@rel;
             IdentitySelectorDiag.logMessage("InformationCardXrds::xrdsListener:onReady", "rel=" + rel);
             var href = linkElt.@href;
             IdentitySelectorDiag.logMessage("InformationCardXrds::xrdsListener:onReady", "href=" + href);
           }
           
           var response = new XML(Components.classes['@mozilla.org/xmlextras/xmlserializer;1'].createInstance(Components.interfaces.nsIDOMSerializer).serializeToString(xrds.documentElement));
           doc.__identityselector__.xrds = response.toXMLString();
           IdentitySelectorDiag.logMessage("InformationCardXrds::xrdsListener:onReady", 
               "response=" + doc.__identityselector__.xrds +
               "doc.location.href=" + doc.location.href);
        } catch(e) {
           IdentitySelectorDiag.logMessage("InformationCardXrds::xrdsListener:onReady", "Error: " + e);
        }
     };
  },

  retrieveXrds : function(doc, hrefStr) {
        IdentitySelectorDiag.logMessage("InformationCardXrds::retrieveXrds: doc=" + doc.location.href + " href=", hrefStr);
        IcXrdsRetrieveX.retrieveX(doc, hrefStr, InformationCardXrds.xrdsListener);
    },

    // ***********************************************************************
    // Method: processHtmlMetaElements
    // <meta http-equiv="X-XRDS-Location" content="http://pamelaproject.com/wptest091/?xrds" />
    // ***********************************************************************
  processHtmlMetaElements : function(event) {
      var browser = gBrowser.selectedTab.linkedBrowser;
      // browser is the XUL element of the browser that's just been selected
      var doc = gBrowser.selectedBrowser.contentDocument;

      var dispatchEvents = true;
      
      //IdentitySelectorDiag.logMessage("InformationCardXrds::processHtmlMetaElements", " start: " + doc.location.href);
        if( doc.wrappedJSObject !== undefined) {
           doc = doc.wrappedJSObject;
           }
        if ((IdentitySelector.hasOwnProperty("disabled")) && (IdentitySelector.disabled === true)) {
           IdentitySelectorDiag.logMessage("InformationCardXrds::processHtmlMetaElements", " ID selector is disabled. Exiting");
           return;
           }
        
        if (!(doc instanceof HTMLDocument)) {
          IdentitySelectorDiag.logMessage("InformationCardXrds::processHtmlMetaElements", " no html document. Exiting");
          return;
        }
        
        if( doc.__identityselector__ === undefined) {
           IdentitySelector.runInterceptScript(doc);
        }

        // <meta http-equiv="X-XRDS-Location" content="http://pamelaproject.com/wptest091/?xrds" />
        var linkElems = doc.getElementsByTagName( "META");
          //IdentitySelectorDiag.logMessage("InformationCardXrds::processHtmlMetaElements: number of META elements=", linkElems.length);
        for( var i = 0; i < linkElems.length; i++) {
           var linkElem = linkElems[ i];
           IdentitySelectorDiag.logMessage("InformationCardXrds::processHtmlMetaElements: meta element=", linkElem);
           var relStr = linkElem.getAttribute( "HTTP-EQUIV");
           if (relStr === null) { continue; }
           if ((relStr === "x-xrds-location") || (relStr === "X-XRDS-Location")) {
              //IdentitySelectorDiag.logMessage("InformationCardXrds::processHtmlMetaElements: X-XRDS-Location i=", i);
              var hrefStr = linkElem.getAttribute( "CONTENT");
              if (hrefStr === null) {
                 continue;
                 }
              else {
                 //IdentitySelectorDiag.logMessage("InformationCardXrds::processHtmlMetaElements: href=", hrefStr);
                 if (doc.__identityselector__.xrds_metadata_href === undefined) {
                   doc.__identityselector__.xrds_metadata_href = hrefStr;
                   InformationCardXrds.retrieveXrds(doc, hrefStr);
                 }
//                 if( doc.__identityselector__.xrds === undefined) {
//                      var data = doc.__identityselector__.data;
//                      InformationCardXrds.retrieveXrds(doc, hrefStr);
////                      if (doc.__identityselector__.data.xrds_metadata_href === undefined) {
////                        doc.__identityselector__.data.xrds_metadata_href = hrefStr;
////                        InformationCardXrds.retrieveXrds(doc, hrefStr);
////                      }                 
//                   }
                 else {
                    IdentitySelectorDiag.logMessage("InformationCardXrds::processHtmlMetaElements: already loaded: href=", hrefStr);
                    }
                 return;
                 }
              }
           else {
              continue;
              }
           }
    },

    // ***********************************************************************
    // Method: processHtmlLinkElements
    // ***********************************************************************
    processHtmlLinkElements : function(event) {
      var browser = gBrowser.selectedTab.linkedBrowser;
      // browser is the XUL element of the browser that's just been selected
      var doc = gBrowser.selectedBrowser.contentDocument;

      var dispatchEvents = true;
      
      //IdentitySelectorDiag.logMessage("InformationCardXrds::processHtmlLinkElements", " start: " + doc.location.href);
        if( doc.wrappedJSObject !== undefined) {
           doc = doc.wrappedJSObject;
           }
        if ((IdentitySelector.hasOwnProperty("disabled")) && (IdentitySelector.disabled === true)) {
           IdentitySelectorDiag.logMessage("InformationCardXrds::processHtmlLinkElements", " ID selector is disabled. Exiting");
           return;
           }
        
        if (!(doc instanceof HTMLDocument)) {
          IdentitySelectorDiag.logMessage("InformationCardXrds::processHtmlLinkElements", " no html document. Exiting");
          return;
        }
        
        if( doc.__identityselector__ === undefined) {
           IdentitySelector.runInterceptScript(doc);
           }
        var linkElems = doc.getElementsByTagName( "LINK");
        for( var i = 0; i < linkElems.length; i++) {
           var linkElem = linkElems[ i];
           var relStr = linkElem.getAttribute( "REL");
           if( (relStr !== null) && (relStr === "xrds.metadata")) {
              var hrefStr = linkElem.getAttribute( "HREF");
              if (hrefStr === null) {
                 continue;
                 }
              else {
                 IdentitySelectorDiag.logMessage("InformationCardXrds::processHtmlLinkElements: href=", hrefStr);
                 if (doc.__identityselector__.xrds_metadata_href === undefined) {
                   doc.__identityselector__.xrds_metadata_href = hrefStr;
                   InformationCardXrds.retrieveXrds(doc, hrefStr);
                 }
                 else {
                    IdentitySelectorDiag.logMessage("InformationCardXrds::processHtmlLinkElements: already loaded: href=", hrefStr);
                    }
                 return;
              }
           } else {
              continue;
           }
        }
    },
    
    processWellknown : function(event) {
      var browser = gBrowser.selectedTab.linkedBrowser;
      // browser is the XUL element of the browser that's just been selected
      var doc = gBrowser.selectedBrowser.contentDocument;

      var dispatchEvents = true;
      
      if( doc.wrappedJSObject !== undefined) {
         doc = doc.wrappedJSObject;
         }
      if ((IdentitySelector.hasOwnProperty("disabled")) && (IdentitySelector.disabled === true)) {
         IdentitySelectorDiag.logMessage("InformationCardXrds::processWellknown", " ID selector is disabled. Exiting");
         return;
         }
      
      if (!(doc instanceof HTMLDocument)) {
        IdentitySelectorDiag.logMessage("InformationCardXrds::processWellknown", " no html document. Exiting");
        return;
      }
      
      if( doc.__identityselector__ === undefined) {
         IdentitySelector.runInterceptScript(doc);
      }
      
      if (doc.__identityselector__.xrds_metadata_href === undefined) {
        var hrefStr;
        if (doc.location) {
          var protocol = doc.location.protocol;
          var host = doc.location.host;
          hrefStr = protocol + "//" + host + "/.well-known/host-meta";
        } else {
          // doc is a string
          var i = doc.indexOf("://");
          if (i>0) {
            var tmp = doc.substring(i+3);
            i = tmp.indexOf("/");
            if (i>0) {
              hrefStr = tmp.substring(0,i) + ".well-known/host-meta";
            } else {
              hrefStr = tmp + "/.well-known/host-meta";
            }
          } else {
            IdentitySelectorDiag.logMessage("InformationCardXrds::processWellknown: strange format: doc=", doc);
            return;
          }
        }
        if (hrefStr) {
          IdentitySelectorDiag.logMessage("InformationCardXrds::processWellknown: href=", hrefStr);
          doc.__identityselector__.xrds_metadata_href = hrefStr;
          InformationCardXrds.retrieveXrds(doc, hrefStr);
        }
      }
      else {
         IdentitySelectorDiag.logMessage("InformationCardXrds::processWellknown: already loaded: href=", 
             doc.__identityselector__.xrds_metadata_href);
      }
    },
        
        onDOMChanged : function(event) {
              var target = event ? event.target : this;
              var doc;

              if( target.wrappedJSObject)
              {
                target = target.wrappedJSObject;
              }

              try
              {
                  if( (doc = target.ownerDocument) === undefined)
                  {
                          return;
                  }
//                if (!(doc instanceof HTMLDocument)) {
//                  IdentitySelectorDiag.logMessage("InformationCardXrds::onDOMChanged", " no html document." + doc.location.href);
//                  return;
//                }

                  if( target instanceof HTMLLinkElement)
                  {
                    var linkElem = target;
                  IdentitySelectorDiag.logMessage("InformationCardXrds::onDOMChanged", "HTMLLinkElement");
                  var relStr = linkElem.getAttribute( "REL");
            if( (relStr !== null) && (relStr === "xrds.metadata")) {
               var hrefStr = linkElem.getAttribute( "HREF");
               if (hrefStr === null) {
                  return;
               }
              IdentitySelectorDiag.logMessage("InformationCardXrds::onDOMChanged: href=", hrefStr);
              if (doc.__identityselector__.xrds_metadata_href === undefined) {
               doc.__identityselector__.xrds_metadata_href = hrefStr;
               InformationCardXrds.retrieveXrds(doc, hrefStr);
              }
              else {
                 IdentitySelectorDiag.logMessage("InformationCardXrds::onDOMChanged: already loaded: href=", hrefStr);
                 }
              return;
            }
                  }
                  if( target instanceof HTMLMetaElement)
                  {
                    // <meta http-equiv="X-XRDS-Location" content="http://pamelaproject.com/wptest091/?xrds" />
                    var linkElem = target;
                  IdentitySelectorDiag.logMessage("InformationCardXrds::onDOMChanged", "HTMLMetaElement");
             var relStr = linkElem.getAttribute( "HTTP-EQUIV");
             if( (relStr !== null) && (relStr === "X-XRDS-Location")) {
              IdentitySelectorDiag.logMessage("InformationCardXrds::onDOMChanged: X-XRDS-Location");
              var hrefStr = linkElem.getAttribute( "CONTENT");
              if (hrefStr !== null) {
                IdentitySelectorDiag.logMessage("InformationCardXrds::onDOMChanged: href=", hrefStr);
                if (doc.__identityselector__.xrds_metadata_href === undefined) {
                 doc.__identityselector__.xrds_metadata_href = hrefStr;
                 InformationCardXrds.retrieveXrds(doc, hrefStr);
                }
              }
             }
                  }

        }
              catch( e)
              {
                      IdentitySelectorDiag.debugReportError( "InformationCardXrds::onDOMChanged", e);
              }
          
        },
        
        onDOMContentLoaded : function(event) {
        var browser = gBrowser.selectedTab.linkedBrowser;
        // browser is the XUL element of the browser that's just been selected
        var doc = gBrowser.selectedBrowser.contentDocument;
        IdentitySelectorDiag.logMessage("InformationCardXrds::onDOMContentLoaded:", "doc=" + doc.location.href);

        if (gObj !== null) {
            doc.addEventListener("http://infocardfoundation.org/service/1.0/login", IcXrdsComponent.handleLoginEvent, false);
            doc.addEventListener("http://infocardfoundation.org/policy/1.0/login", IcXrdsComponent.handlePolicyEvent, false);
        } else {
          var target = event.originalTarget;
          if (target instanceof HTMLDocument) {
            this.processHtmlMetaElements(null);
            this.processHtmlLinkElements(null);
          }
        }
        }
};

//**************************************************************************
//Desc:
//**************************************************************************

var XrdsStateChangeListener =
{
    QueryInterface : function( aIID)
    {
            if( aIID.equals( Components.interfaces.nsIWebProgressListener) ||
                     aIID.equals( Components.interfaces.nsISupportsWeakReference) ||
                     aIID.equals( Components.interfaces.nsISupports))
            {
                    return( this);
            }
           
            throw Components.results.NS_NOINTERFACE;
    },

    onProgressChange : function() { return( 0); },
   
    onStatusChange : function() { return( 0); },
   
    onLocationChange: function(aProgress, aRequest, aURI) {},
    
    onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) {
      var progListIFace = Components.interfaces.nsIWebProgressListener;
        if( aFlag & progListIFace.STATE_STOP) {
          if( aFlag & progListIFace.STATE_IS_WINDOW) {
            IdentitySelectorDiag.logMessage( "XrdsStateChangeListener.onStateChange",
                                "stop status code = " + aStatus);
                if( aStatus === 0) {
                  try {
                    var doc = aWebProgress.DOMWindow.document;
                    InformationCardXrds.processHtmlMetaElements(doc);
                    } catch(e) {
                      IdentitySelectorDiag.logMessage("XrdsStateChangeListener.onStateChange", "Error: " + e);
                    }
                }
          }
        }
    },

    onSecurityChange : function(aWebProgress, aRequest, aState) {}
};

var IcXrdsStartHelper = {
  onLoad : function(event) {
    window.removeEventListener( "load", function(event){gBrowser.addEventListener("load", InformationCardXrds.onLoad(event), true);}, false);
    if (!(event.originalTarget instanceof HTMLDocument)) {
      IdentitySelectorDiag.logMessage( "IcXrdsStartHelper", "onLoad: is no HTMLDocument");
      return;
    }
    if (event.originalTarget.defaultView.frameElement) {
      IdentitySelectorDiag.logMessage( "IcXrdsStartHelper", "onLoad: inside frame");
      return;
    }
    var doc = event.originalTarget;

    IdentitySelectorDiag.logMessage( "InformationCardXrds", "onLoad: doc.location.href=" + doc.location.href);
    
    // try to use the xrds_pageinfo.xpi component
    var CONTRACT_ID = "@openinfocard.org/xrds;1";

      gObj = null;
      try {
        var cidClass = Components.classes[CONTRACT_ID];
      if (cidClass !== undefined) {
        gObj = cidClass.createInstance();
        gObj = gObj.QueryInterface(Components.interfaces.IXrdsComponent);
      } else {
        IdentitySelectorDiag.logMessage("InformationCardXrds", "the class " + CONTRACT_ID + " is not installed");
      }
      } catch(e1) {
        IdentitySelectorDiag.reportError("InformationCardXrds exception:", e1);
      }
      
      if (gObj !== null) {
//      window.addEventListener("DOMContentLoaded", 
//          function(evnt) {InformationCardXrds.onDOMContentLoaded(evnt);}, false );

        var parser = Components.classes["@mozilla.org/xmlextras/domparser;1"]
                                      .createInstance(Components.interfaces.nsIDOMParser);

        var serviceType = "http://infocardfoundation.org/service/1.0/login";
        var xrdsStr = gObj.getXrdsForSite(doc.location.href, serviceType);
        if (xrdsStr !== null) {
          IcXrdsComponent.logMessage( "InformationCardXrds::InformationCardXrds::onLoad", "type=" + serviceType + " doc.location.href="+doc.location.href + " xrds=" + xrdsStr);
          var serviceDoc = parser.parseFromString(xrdsStr, "text/xml");
          IcXrdsComponent.handleLogin(serviceDoc, doc);
        }
        serviceType = "http://infocardfoundation.org/policy/1.0/login";
        xrdsStr = gObj.getXrdsForSite(doc.location.href, serviceType);
        if (xrdsStr !== null) {
          IcXrdsComponent.logMessage( "InformationCardXrds::InformationCardXrds::onLoad", "type=" + serviceType + " doc.location.href="+doc.location.href + " xrds=" + xrdsStr);
          var policyDoc = parser.parseFromString(xrdsStr, "text/xml");
          IcXrdsComponent.handlePolicy(policyDoc, doc);
        }

        IdentitySelectorDiag.logMessage("InformationCardXrds::InformationCardXrds::onLoad", "adding event listeners");
        // add the event handlers. The events will be triggered by the component.
        doc.addEventListener("http://infocardfoundation.org/service/1.0/login", IcXrdsComponent.handleLoginEvent, false);
        doc.addEventListener("http://infocardfoundation.org/policy/1.0/login", IcXrdsComponent.handlePolicyEvent, false);
      } else {
      IdentitySelectorDiag.logMessage("InformationCardXrds::InformationCardXrds::onLoad", "The class " + CONTRACT_ID + " is not installed");
      window.addEventListener("ICDOMChanged",
                    function(evnt) {InformationCardXrds.onDOMChanged(evnt);}, false);
      window.addEventListener("DOMContentLoaded", 
          function(evnt) {InformationCardXrds.processHtmlLinkElements(evnt);}, false );
      window.addEventListener("DOMContentLoaded", 
          function(evnt) {InformationCardXrds.processHtmlMetaElements(evnt);}, false );
      window.addEventListener("DOMContentLoaded", 
          function(evnt) {InformationCardXrds.processWellknown(evnt);}, false );
      window.getBrowser().addProgressListener( XrdsStateChangeListener,
                  Components.interfaces.nsIWebProgress.NOTIFY_STATE_ALL);
    }
  },
  
  onUnload : function(event) {
    IdentitySelectorDiag.logMessage("InformationCardXrds::InformationCardXrds", "onUnload");
    window.removeEventListener("DOMContentLoaded", 
        function(evnt) {InformationCardXrds.processHtmlLinkElements(evnt);}, false );
    window.removeEventListener("DOMContentLoaded", 
        function(evnt) {InformationCardXrds.processHtmlMetaElements(evnt);}, false );
  }
  
};


try {
  IdentitySelectorDiag.logMessage("InformationCardXrds::InformationCardXrds", "start");
  
    window.addEventListener( "load", function(event){gBrowser.addEventListener("load", IcXrdsStartHelper.onLoad, true);}, false);
           
    window.addEventListener( "unload", IcXrdsStartHelper.onUnload, false);
} catch( e) {
  IdentitySelectorDiag.reportError( "InformationCardXrds window.addEventListener failed: ", e);
}
