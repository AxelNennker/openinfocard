var StreamListener = function(aChannel, anOpenIdRpInstance, logService) {
  this.mChannel = aChannel;
  this.anOpenIdRpInstance = anOpenIdRpInstance;
  this.logService = logService;
};

StreamListener.prototype = {
  mData : "",
  mChannel : null,
  mOpenIdRpInstance : null,
  
  // nsIStreamListener
  onStartRequest : function(aRequest, aContext) {
    this.mData = "";
  },

  onDataAvailable : function(aRequest, aContext, aStream, aSourceOffset,
      aLength) {
    var scriptableInputStream = Components.classes["@mozilla.org/scriptableinputstream;1"]
        .createInstance(Components.interfaces.nsIScriptableInputStream);
    scriptableInputStream.init(aStream);

    this.mData += scriptableInputStream.read(aLength);
  },

  onStopRequest : function(aRequest, aContext, aStatus) {
    if (Components.isSuccessCode(aStatus)) {
      // request was successfull
      this.anOpenIdRpInstance.checkimmediateCallback(aStatus, this.mData);
    } else {
      // request failed
      this.anOpenIdRpInstance.checkimmediateCallback(aStatus, null);
    }

    this.mChannel = null;
  },

  // nsIChannelEventSink
  onChannelRedirect : function(aOldChannel, aNewChannel, aFlags) {
    // if redirecting, store the new channel
    this.mChannel = aNewChannel;
  },

  // nsIInterfaceRequestor
  getInterface : function(aIID) {
    this.mOpenIdRpInstance.logService.logStringMessage('openidRP QueryInterface: aIID=' + aIID);
    try {
      return this.QueryInterface(aIID);
    } catch (e) {
      this.mOpenIdRpInstance.logService.logStringMessage('openidRP QueryInterface: exception=' + e);
      throw Components.results.NS_NOINTERFACE;
    }
  },

  // nsIProgressEventSink (not implementing will cause annoying exceptions)
  onProgress : function(aRequest, aContext, aProgress, aProgressMax) {
  },
  onStatus : function(aRequest, aContext, aStatus, aStatusArg) {
  },

  // nsIHttpEventSink (not implementing will cause annoying exceptions)
  onRedirect : function(aOldChannel, aNewChannel) {
//    this.mOpenIdRpInstance.logService.logStringMessage('openidRP StreamListener: onRedirect: aOldChannel.URI=' + aOldChannel.URI);
//    dump('openidRP StreamListener: aOldChannel.URI=' + aOldChannel.URI);
//    dump('openidRP StreamListener: aOldChannel.responseStatus=' + aOldChannel.responseStatus);
//    dump('openidRP StreamListener: aNewChannel.URI=' + aNewChannel.URI);
  },

  // we are faking an XPCOM interface, so we need to implement QI
  QueryInterface : function(aIID) {
    this.mOpenIdRpInstance.logService.logStringMessage('openidRP QueryInterface: aIID=' + aIID);
    if (aIID.equals(Components.interfaces.nsISupports)
        || aIID.equals(Components.interfaces.nsIInterfaceRequestor)
        || aIID.equals(Components.interfaces.nsIChannelEventSink)
        || aIID.equals(Components.interfaces.nsIProgressEventSink)
        || aIID.equals(Components.interfaces.nsIHttpEventSink)
        || aIID.equals(Components.interfaces.nsIStreamListener)) {
      return this;
    }
    throw Components.results.NS_NOINTERFACE;
  }
};

function myHttpRequest(myURLString, anOpenIdRpInstance) {
  this.mOpenIdRpInstance = anOpenIdRpInstance;
  // the IO service
  var ioService = Components.classes["@mozilla.org/network/io-service;1"]
      .getService(Components.interfaces.nsIIOService);
  // create an nsIURI
  var uri = ioService.newURI(myURLString, null, null);
  // get a channel for that nsIURI
  this.mChannel = ioService.newChannelFromURI(uri);
  // get an listener
  this.listener = new StreamListener(this.mChannel, anOpenIdRpInstance);
  this.mChannel.notificationCallbacks = this.listener;
  this.mChannel.asyncOpen(this.listener, null);
}

function openidRP(server, finalizeOpenId, aDoc, extraParamsOpenIDAuthParameters) {
  this.logService = Components.classes["@mozilla.org/consoleservice;1"]
      .getService(Components.interfaces.nsIConsoleService);
  this.server = server;
  this.finalizeOpenId = finalizeOpenId;
  this.aDoc = aDoc;
  this.extraParamsOpenIDAuthParameters = extraParamsOpenIDAuthParameters;
  this.user_setup_url = null;
  this.checkimmediateRequest = null;
}

openidRP.prototype = {
  setParams : function(server, finalizeOpenId, aDoc,
      extraParamsOpenIDAuthParameters) {
    this.server = server;
    this.logService.logStringMessage('setParams: this.server=' + this.server);
    this.finalizeOpenId = finalizeOpenId;
    this.aDoc = aDoc;
    this.extraParamsOpenIDAuthParameters = extraParamsOpenIDAuthParameters;
  },

  updateProgress : function(evt) {
    try {
      var label = document.getElementById("notify");
      if (evt.lengthComputable) {
        var percentComplete = evt.loaded / evt.total;
        label.setAttribute('value',
            'PercentComplete: ' + percentComplete);
        this.logService
            .logStringMessage('PercentComplete: ' + percentComplete);
      } else {
        label.setAttribute('value', 'PercentComplete: 100');
        this.logService.logStringMessage('PercentComplete: 100');
      }
    } catch (e) {
      this.logService.logStringMessage('updateProgress: exception:' + e);
    }
  },

  onStateChange : function(aProgress, aRequest, aFlag, aStatus) {
    var progListIFace = Components.interfaces.nsIWebProgressListener;

    // Log the flags

    this.logService.logMessage("openidRP.onStateChange", "flags = "
        + aFlag);

    if (aFlag & progListIFace.STATE_IS_DOCUMENT) {
      this.logService.logMessage("openidRP.onStateChange",
          "flag & document");
    }

    if (aFlag & progListIFace.STATE_IS_WINDOW) {
      this.logService.logMessage("openidRP.onStateChange",
          "flag & window");
    }

    if (aFlag & progListIFace.STATE_START) {
      this.logService.logMessage("openidRP.onStateChange",
          "flag & start");
    }

    if (aFlag & progListIFace.STATE_STOP) {
      this.logService.logMessage("openidRP.onStateChange",
          "flag & stop");
    }

    // Process the document.  The 'STOP' state isn't reached until after
    // the page is fully loaded and all onload events have completed.
    // We need to re-process the page in case an onload event added
    // information card elements or objects to the page.  An example of
    // a page that does this is login.live.com.

    if (aFlag & progListIFace.STATE_STOP) {
      if (aFlag & progListIFace.STATE_IS_WINDOW) {
        this.logService.logMessage("onStateChange",
            "stop status code = " + aStatus);

        if (aStatus === 0) {
        }
      }
    }

    return (0);
  },

  onLocationChange : function(aProgress, aRequest, aURI) {
    // This fires when a load event has been confirmed or when the
    // user switches tabs.  At this point, Firefox has created a skeletal
    // document into which the source document will be loaded.
    try {
      this.logService.debugReportError(
          "openidRP.onLocationChange location=",
          aProgress.DOMWindow.document.location);
    } catch (e) {
      this.logService.debugReportError("openidRP.onLocationChange",
          e);
    }

    return (0);
  },

  onProgressChange : function() {
    return (0);
  },

  onStatusChange : function() {
    return (0);
  },

  onSecurityChange : function() {
    return (0);
  },

  onLinkIconAvailable : function() {
    return (0);
  },

  checkimmediateCallback : function(status, data) {
    this.logService.logStringMessage("checkimmediateCallback Status=" + status);
    if (data !== null) {
      this.logService.logStringMessage("checkimmediateCallback Data=" + data);
    }
    this.checkimmediateRequest = null;

    var label = document.getElementById("notify");
    if (label !== null) {
      label.setAttribute("value", "checkimmediate finished");
    }
    //        var user_setup_url = this.getParam(url, "openid.user_setup_url");
    //      var openid_mode=this.getParam(url, "openid.mode");

    var user_setup_url = this.user_setup_url;
    if (!user_setup_url) {
      if (label !== null) {
        label.setAttribute("value", "checkimmediate returned an unexpected result");
        return;
      }
    }
    var anUri = this.urlDecode(user_setup_url);
    this.logService.logStringMessage("checkimmediateCallback anUri=" + anUri);
    
    if (anUri.indexOf("openid.claimed_id") < 0) {
      // need to fix the setup_url openid.claimed_id is required
      var openidIdentity = this.getParam(anUri, "openid.identity");
      if (openidIdentity) {
        this.logService.logStringMessage("checkimmediateCallback adding claimed_id=" + openidIdentity);
        anUri += "&openid.claimed_id=" + openidIdentity;
        this.logService.logStringMessage("checkimmediateCallback added claimed_id anUri=" + anUri);
      }
    }
    
//    var extraParams;
//    if (this.extraParamsOpenIDAuthParameters !== undefined) {
//      this.logService.logStringMessage("checkimmediateCallback this.extraParamsOpenIDAuthParameters = "
//              + this.extraParamsOpenIDAuthParameters);
//      extraParams = this._extraParamsToUrl(this.extraParamsOpenIDAuthParameters);
//      this.logService.logStringMessage("checkimmediateCallback extraParams = "
//          + extraParams);
//    } else {
//      this.logService.logStringMessage("checkimmediateCallback this.extraParamsOpenIDAuthParameters = undefined");
//      extraParams = "";
//    }

//    anUri += extraParams;
    
    if (label !== null) {
      label.setAttribute("value", "user_setup_url: " + anUri);
    }
    this.logService
        .logStringMessage("checkimmediateCallback: anUri="
            + anUri);
    if ((this.finalizeOpenId) && (typeof(this.finalizeOpenId) == 'function')) {
      this.finalizeOpenId(this.logService, anUri, null);
    } else {
      this.logService.logStringMessage("checkimmediate this.finalizeOpenId is not properly set");
    }

//    var iframe = document.getElementById('openid_iframe');
//    iframe.setAttribute('src', anUri);
//    iframe.setAttribute('hidden', false);
  },

  checkimmediateNew : function(uri) {
    this.checkimmediateRequest = new myHttpRequest(uri, this);
    this.logService.logStringMessage("checkimmediateNew " + uri);
  },

  checkimmediate : function(uri) {
    var req = new XMLHttpRequest();
    req.open('GET', uri, false);
    req.setRequestHeader("User-Agent", "xmldap openid stack");
    //      this.logService.logStringMessage("checkimmediate: typeof(that.updateProgress)=" + typeof(that.updateProgress));
    //      var that = this;
    //      req.addEventListener("progress", function(event) { that.updateProgress(event); }, false); 
    var label = document.getElementById("notify");
    if (label !== null) {
      label.setAttribute("value", "checkimmediate " + uri);
    }
    try {
      req.send(null);
    } catch (e) {
      this.logService
          .logStringMessage("openidRP checkimmediate exception: " + e);
      if ((this.finalizeOpenId !== undefined)
          && (this.finalizeOpenId !== null)
          && (typeof (this.finalizeOpenId) == 'function')) {
        var identity = this.getParam(uri, "openid.identity");
        this.logService.logStringMessage("checkimmediate identity=" + identity);
        // newFinalizeOpenId(url, error)
        this.finalizeOpenId(this.logService, null, "" + e);
      }
      return;
    }
    if (req.status == 200) {
      if (label !== null) {
        label.setAttribute("value", "checkimmediate ok");
      }
      //          var user_setup_url = this.getParam(url, "openid.user_setup_url");
      //        var openid_mode=this.getParam(url, "openid.mode");

      var resp = req.responseText;
      this.logService.logStringMessage("checkimmediate: resp=" + resp);
      var allHeaders = req.getAllResponseHeaders();
      this.logService.logStringMessage("checkimmediate: allHeaders="
          + allHeaders);
      var user_setup_url = this.user_setup_url;
      if (!user_setup_url) {
         this.logService.logStringMessage("checkimmediate: user_setup_url is undefined!");
         return;
      }
      if (label !== null) {
        label
            .setAttribute("value", "user_setup_url: "
                + user_setup_url);
      }
      var iframe = document.getElementById('openid_iframe');
      var anUri = this.urlDecode(user_setup_url);
      this.logService.logStringMessage("checkimmediate: user_setup_url="
          + user_setup_url);
      this.logService.logStringMessage("checkimmediate: anUri:"
          + anUri);
      iframe.setAttribute('src', anUri);
    } else {
      this.logService
          .logStringMessage('openidRP.checkimmediate returned: ' + req.status);
    }
  },

  getParam : function(query, param) {
      var q = query.indexOf('?');
      if (q > -1) {
        query = query.substring(q+1);
      }
    var vars = query.split("&");
    for ( var i = 0; i < vars.length; i++) {
      var pair = vars[i].split("=");
      if (pair[0] == param) {
        return pair[1];
      }
    }
    return null;
  },

  _urlEncode : function(str2encode) {
    var utftext = "";

    for ( var n = 0; n < str2encode.length; n++) {

      var c = str2encode.charCodeAt(n);

      if (c < 128) {
        utftext += String.fromCharCode(c);
      } else if ((c > 127) && (c < 2048)) {
        utftext += String.fromCharCode((c >> 6) | 192);
        utftext += String.fromCharCode((c & 63) | 128);
      } else {
        utftext += String.fromCharCode((c >> 12) | 224);
        utftext += String.fromCharCode(((c >> 6) & 63) | 128);
        utftext += String.fromCharCode((c & 63) | 128);
      }

    }
    return encodeURI(utftext);
  },

  urlDecode : function(str2decode) {

    var utftext = unescape(str2decode);

    str2decode = "";
    var i = 0;
    var c = 0;
    var c1 = 0;
    var c2 = 0;

    while (i < utftext.length) {

      c = utftext.charCodeAt(i);

      if (c < 128) {
        str2decode += String.fromCharCode(c);
        i++;
      } else if ((c > 191) && (c < 224)) {
        c2 = utftext.charCodeAt(i + 1);
        str2decode += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
        i += 2;
      } else {
        c2 = utftext.charCodeAt(i + 1);
        var c3 = utftext.charCodeAt(i + 2);
        str2decode += String.fromCharCode(((c & 15) << 12)
            | ((c2 & 63) << 6) | (c3 & 63));
        i += 3;
      }

    }
    return str2decode;
  },

  _extraParamsToUrl : function(extraParams) {
    extraParams = extraParams.replace(/\r\n/g, "\n");
    var url = "";
    var paramLines = extraParams.split('\n');
    this.logService.logStringMessage("_extraParamsToUrl paramLines.length=" + paramLines.length);
    if (paramLines.length === 1) {
      paramLines = extraParams.split(' ');
    }
    this.logService.logStringMessage("_extraParamsToUrl paramLines.length=" + paramLines.length);
    for ( var i = 0; i < paramLines.length; i++) {
      var line = paramLines[i];
      this.logService.logStringMessage("_extraParamsToUrl line=" + line);
      var colonIndex = line.indexOf(':');
      var regexp = new RegExp("[\\s]+", "g");
      var name = line.substring(0, colonIndex).replace(regexp, "");
      var value = line.substring(colonIndex + 1);
      value = value.replace(regexp, "");
      url = url + '&' + this._urlEncode(name) + '='
          + this._urlEncode(value);
    }
    return url;
  },

  registerSetupUrl : function(url) {
    this.logService.logStringMessage("openidrp registerSetupUrl: URL=" + url);
    var openid_setup_url = this.getParam(url, "openid.user_setup_url");
    this.logService.logStringMessage("openidrp registerSetupUrl: openid.user_setup_url="
        + openid_setup_url);
    this.user_setup_url = openid_setup_url;
  },

  registerOpenId : function(openid_return_to_url) {
    this.logService.logStringMessage("openidrp registerOpenId: "
        + openid_return_to_url);

    if (!this.aDoc) return; // not initialized
    // FIXME the code should store the channel in the request and verify it in the response
    
    var openid_mode = this.getParam(openid_return_to_url, "openid.mode");
    this.logService.logStringMessage("openidrp registerOpenId: openid.mode=" + openid_mode);

    if (openid_mode == "id_res") {
      this.aDoc.location = openid_return_to_url;
      if ((this.finalizeOpenId !== undefined)
          && (this.finalizeOpenId !== null)
          && (typeof (this.finalizeOpenId) == 'function')) {
        // var identity = this.getParam(openid_return_to_url, "openid.identity");
        this.finalizeOpenId(this.logService, openid_return_to_url, null);
      }
    } else if (openid_mode == "error") {
      var openid_error = this.getParam(openid_return_to_url,
          "openid.error");
      this.logService.logStringMessage("openidrp registerOpenId: openid.mode="
              + openid_mode + " openid.error=" + openid_error);
      if ((this.finalizeOpenId !== undefined)
          && (this.finalizeOpenId !== null)
          && (typeof (this.finalizeOpenId) == 'function')) {
        // newFinalizeOpenId(url, error)
        this.finalizeOpenId(this.logService, this.logService, null, openid_error);
      }
    } else {
      this.logService.logStringMessage("openidrp registerOpenId: UNHANDLED openid.mode=" + openid_mode);
    }
  },

  // TODO this is not very correct! Should prefer https
  normalize : function() {
    var openid_url;
    if (this.server.indexOf('http') !== 0) {
      openid_url = "http://" + this.server;
    } else {
      openid_url = this.server;
    }
    return openid_url;
  },

  handleDiscoveryResponseHtml : function(resp, openid_url) {
    var serverIndex = resp.indexOf("openid.server");
    var next = resp.substring(serverIndex);
    var hrefIndex = next.indexOf("href=");
    hrefIndex += 6;
    var subStr = next.substring(hrefIndex);
    var endAddr = subStr.indexOf('"');
    var openidServer = subStr.substring(0, endAddr);
    this.logService.logStringMessage("Openid: " + openidServer);
    try {
      var extraParams;
      if (this.extraParamsOpenIDAuthParameters !== undefined) {
        this.logService.logStringMessage("this.extraParamsOpenIDAuthParameters = "
                + this.extraParamsOpenIDAuthParameters);
        extraParams = this._extraParamsToUrl(this.extraParamsOpenIDAuthParameters);
        this.logService.logStringMessage("extraParams = "
            + extraParams);
      } else {
        this.logService.logStringMessage("this.extraParamsOpenIDAuthParameters = undefined");
        extraParams = "";
      }
      if (extraParams !== null && extraParams.indexOf("openid.ns") < 0) {
        // add openid.ns
        extraParams += "openid.ns=http://specs.openid.net/auth/2.0";
      }
      var url = openidServer + "?openid.identity=http://specs.openid.net/auth/2.0/identifier_select"
        + " openid.claimed_id=" + openid_url
        + "&openid.mode=checkid_immediate" + extraParams;
      this.logService.logStringMessage('Performing check_immediate: ' + url);
      var encodedUrl = this._urlEncode(url);
      this.checkimmediateNew(encodedUrl);
    } catch (ex) {
      this.logService.logStringMessage("Error loading remote iframe: " + ex);
      if ((this.finalizeOpenId !== undefined)
          && (this.finalizeOpenId !== null)
          && (typeof (this.finalizeOpenId) == 'function')) {
        // newFinalizeOpenId(url, error)
        this.finalizeOpenId(this.logService, null, ""+ex);
      } else {
        throw "openid discovery failed: " + ex;
      }
    }
  },

  retrieveXrds : function(xrds_location) {
    var req;
    try {
      this.logService.logStringMessage("X-XRDS-Location: " + xrds_location);
      // continue work here and retrieve the xrds file and then parse it
      // Content-Type application/xrds+xml
      req = new XMLHttpRequest();
      req.open('GET', xrds_location, false);
      req.overrideMimeType("text/xml");
      req.setRequestHeader("User-Agent", "xmldap openid stack");
      req.setRequestHeader('Content-Type', "application/xrds+xml");  
      req.setRequestHeader('Accept', "application/xrds+xml");  
      try {
        req.send(null);
      } catch (e) {
        this.logService.logStringMessage("openidRP doit exception: " + e);
        if ((this.finalizeOpenId !== undefined)
            && (this.finalizeOpenId !== null)
            && (typeof (this.finalizeOpenId) == 'function')) {
          // newFinalizeOpenId(url, error)
          this.finalizeOpenId(this.logService, null, "" + e);
        }
        return;
      }
      if (req.status == 200) {
        this.logService.logStringMessage("retrieveXrds responseText: " + req.responseText);
        return req.responseXML;
      } else {
        if ((this.finalizeOpenId !== undefined)
            && (this.finalizeOpenId !== null)
            && (typeof (this.finalizeOpenId) == 'function')) {
          // newFinalizeOpenId(url, error)
          this.finalizeOpenId(this.logService, null, "" + req.statusText); // TODO is this correct?
        } else {
          throw "openid discovery failed! status=" + req.status + " " + req.statusText;
        }
      }
    } catch (e) {
      if ((this.finalizeOpenId !== undefined)
          && (this.finalizeOpenId !== null)
          && (typeof (this.finalizeOpenId) == 'function')) {
        // newFinalizeOpenId(url, error)
        this.finalizeOpenId(this.logService, null, "status=" +req.status + " " + req.statusText); // TODO is this correct?
      } else {
        throw "openid discovery failed!" + e;
      }
    }
  },

//  <?xml version="1.0" encoding="UTF-8"?>
//  <xrds:XRDS
//      xmlns:xrds="xri://$xrds"
//      xmlns:openid="http://openid.net/xmlns/1.0"
//      xmlns="xri://$xrd*($v*2.0)">
//    <XRD>
//   
//      <Service priority="0">
//        <Type>http://specs.openid.net/auth/2.0/signon</Type>
//        <Type>http://openid.net/sreg/1.0</Type>
//        <Type>http://openid.net/extensions/sreg/1.1</Type>
//        <Type>http://schemas.openid.net/pape/policies/2007/06/phishing-resistant</Type>
//        <Type>http://schemas.openid.net/pape/policies/2007/06/multi-factor</Type>
//        <Type>http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical</Type>
//        <URI>https://pip.verisignlabs.com/server</URI>
//              <LocalID>https://ignisvulpis.pip.verisignlabs.com/</LocalID>
//            </Service>
//   
//      <Service priority="1">
//        <Type>http://openid.net/signon/1.1</Type>
//        <Type>http://openid.net/sreg/1.0</Type>
//        <Type>http://openid.net/extensions/sreg/1.1</Type>
//        <URI>https://pip.verisignlabs.com/server</URI>
//              <openid:Delegate>https://ignisvulpis.pip.verisignlabs.com/</openid:Delegate>
//            </Service>
//   
//    </XRD>
//  </xrds:XRDS>

  handleRetrievedXrds : function(xrds, openid_url) {
    var sortedServices = [];
    var services;
    var openidns;
    try {
      this.logService.logStringMessage("handleRetrievedXrds openid_url=" + openid_url);

      var label = document.getElementById("notify");
      if (label) {
        label.setAttribute("value", "parsing discovered XRDS");
      }
      this.logService.logStringMessage("handleRetrievedXrds extraParamsOpenIDAuthParameters=" + 
          this.extraParamsOpenIDAuthParameters );
      services = xrds.getElementsByTagNameNS("xri://$xrd*($v*2.0)", "Service");
      for (var i=0; i<services.length; i++) {
        var service = services[i];
        var priority = service.getAttribute("priority");
        this.logService.logStringMessage("handleRetrievedXrds priority=" + priority);
        if ((priority === null) || (priority == "")) {
          priority = "0";
        }
        if (sortedServices[priority] === undefined) {
          sortedServices[priority] = [];
        }
        sortedServices[priority].push(service);
      }
    } catch (e) {
      this.logService.logStringMessage("handleRetrievedXrds exception=" + e );
      throw e;
    }
    try {
      var protocol = "";
      if (this.extraParamsOpenIDAuthParameters) {
        var openidNSindex = this.extraParamsOpenIDAuthParameters.indexOf("openid.ns:");
        if (openidNSindex >= 0) {
          openidNSindex += 10; // strlen("openid.ns:")
          var prtcl = this.extraParamsOpenIDAuthParameters.substring(openidNSindex);
          var k = 0;
          while (k < prtcl.length) {
            var ch = prtcl.charCodeAt(k);
            if ((ch === 32) || (ch === 13) || (ch === 10)) {
              break;
            }
            protocol += String.fromCharCode(ch);
            k++;
          }
        }
      }
      this.logService.logStringMessage("retrieveXrds protocol=\"" + protocol + "\"");
      var matchingService = null;
      for (var i=0; i<sortedServices.length; i++) {
        services = sortedServices[i];
        for (var j=0; i<services.length; i++) {
          // infocard: getCardId: extraParams[1] = {"OpenIDAuthParameters":"
          //  openid.ns:http://specs.openid.net/auth/2.0 
          //  openid.return_to:https://xmldap.org/xmldap_oc/return_to 
          //  openid.realm:https://xmldap.org/ 
          //  openid.ns.sreg:http://openid.net/extensions/sreg/1.1 
          //  openid.sreg.required:nickname,email 
          //  openid.sreg.optional:fullname,country,timezone 
          //  openid.ns.pape:http://specs.openid.net/extensions/pape/1.0 
          //  openid.pape.preferred_auth_policies:http://schemas.openid.net/pape/policies/2007/06/phishing-resistant"}

          var service = services[j];
          var types = service.getElementsByTagNameNS("xri://$xrd*($v*2.0)", "Type");
          if (protocol.length > 0) {
            for (var m=0; m<types.length; m++) {
              var type = types[m];
              var typeStr = "" + type.firstChild.data + "";
              this.logService.logStringMessage("retrieveXrds Protocol=\"" + protocol + "\"");
              if (typeStr.indexOf(protocol) === 0) {
                this.logService.logStringMessage("retrieveXrds TYPE=" + typeStr);
                matchingService = {};
                matchingService.service = service;
              } else {
                this.logService.logStringMessage("retrieveXrds type=" + typeStr);
              }
            }
          } else {
            // if protocol is "" then match the first service
            matchingService = {};
            matchingService.service = service;
            for (var mm=0; mm<types.length; mm++) {
              var type = types[mm];
              var typeStr = "" + type.firstChild.data + "";
              if (typeStr.indexOf("http://specs.openid.net/auth/2.0/signon") === 0) {
                openidns = "http://specs.openid.net/auth/2.0";
                break;
              }
              if (typeStr.indexOf("http://openid.net/signon/1.1") === 0) {
                openidns = "http://openid.net/signon/1.1";
                break;
              }
            }
          }
          var uris = service.getElementsByTagNameNS("xri://$xrd*($v*2.0)", "URI");
          var uri;
          if (uris.length > 0) {
            uri = uris[0];
            this.logService.logStringMessage("handleRetrievedXrds URI=" + uri.firstChild.data);
            if (matchingService !== null) {
              matchingService.uri = uri.firstChild.data;
            }
          }
          var localIds = service.getElementsByTagNameNS("xri://$xrd*($v*2.0)", "LocalID");
          var localId;
          if (localIds.length > 0) {
            localId = localIds[0];
            this.logService.logStringMessage("handleRetrievedXrds localId=" + localId.firstChild.data);
            if (matchingService !== null) {
              matchingService.localId = localId.firstChild.data;
            }
          }
          var delegates = service.getElementsByTagNameNS("http://openid.net/xmlns/1.0", "Delegate");
          var delegate;
          if (delegates.length > 0) {
            delegate = delegates[0];
            this.logService.logStringMessage("handleRetrievedXrds delegate=" + delegate.firstChild.data);
            if (matchingService !== null) {
              matchingService.delegate = delegate.firstChild.data;
            }
          }
        }
        if (matchingService !== null) {
          break;
        }
      } // for
      if (matchingService !== null) {
        var id;
        if (!matchingService.localId) {
          this.logService.logStringMessage("handleRetrievedXrds: localId is undefined. openid_url=" + openid_url);
          // assume that this.server is the full openid
          id = this._urlEncode("" + openid_url);
          this.logService.logStringMessage("handleRetrievedXrds: localId is undefined. Using: " + id);
        } else {
          id = this._urlEncode(matchingService.localId);
        }
        var extraParams;
        if (this.extraParamsOpenIDAuthParameters) {
          extraParams = this._extraParamsToUrl(this.extraParamsOpenIDAuthParameters);
        } else {
          extraParams = "";
        }
        var url = matchingService.uri + "?openid.identity=" + id
        + "&openid.claimed_id=" + id
        + "&openid.mode=checkid_immediate" 
        + extraParams;
        this.logService.logStringMessage('handleRetrievedXrds: Performing check_immediate: ' + url);
        var label = document.getElementById("notify");
        if (label) {
          label.setAttribute("value", "check immediate: " + url);
        }
        if (url && url.indexOf("openid.ns") < 0) {
          if (openidns) {
            url += "&openid.ns=" + openidns;
          } else {
            url += "&openid.ns=http://specs.openid.net/auth/2.0";
          }
        }
        var encodedUrl = this._urlEncode(url);
        this.checkimmediateNew(encodedUrl);
      } else {
        this.logService.logStringMessage("handleRetrievedXrds no matching service found!");
        if ((this.finalizeOpenId !== undefined)
            && (this.finalizeOpenId !== null)
            && (typeof (this.finalizeOpenId) == 'function')) {
          // newFinalizeOpenId(attributes, verified_id, openidServer, error)
          this.finalizeOpenId(this.logService, null, "no matching service found");
        }
      }
    } catch(ee) {
      this.logService.logStringMessage("handleRetrievedXrds Exception=" + ee );
      throw ee;
    }
  },

  discover : function(openid_url) {
    var label = document.getElementById("notify");
    if (label) {
      label.setAttribute("value", "discovery for " + openid_url);
    }
    var req = new XMLHttpRequest();
    req.open('GET', openid_url, false);
    req.setRequestHeader("User-Agent", "xmldap openid stack");
    req.setRequestHeader('Accept', "application/xrds+xml");  
    try {
      req.send(null);
    } catch (e) {
      this.logService.logStringMessage("openidRP doit exception: " + e);
      if ((this.finalizeOpenId !== undefined)
          && (this.finalizeOpenId !== null)
          && (typeof (this.finalizeOpenId) == 'function')) {
        // newFinalizeOpenId(url, error)
        this.finalizeOpenId(this.logService, null, "" + e);
      }
      return;
    }
    if (req.status == 200) {
      this.logService.logStringMessage('discover: ' + req.getAllResponseHeaders());
      var resp = req.responseText;
      this.logService.logStringMessage('discover: ' + resp);
      var respContentType = req.getResponseHeader("Content-Type");
      this.logService.logStringMessage('respContentType: ' + respContentType);
      // respContentType: application/xrds+xml;charset=ISO-8859-1
      if ((respContentType) && (respContentType.indexOf("application/xrds+xml") >= 0)) {
        this.logService.logStringMessage('typeof(req.responseXML)= ' + typeof(req.responseXML));
        this.handleRetrievedXrds(req.responseXML, openid_url);
      } else {
        // X-XRDS-Location: https://pip.verisignlabs.com/user/ignisvulpis/yadisxrds
        var xrds_location = req.getResponseHeader("X-XRDS-Location");
        if (xrds_location !== null) {
          var xrds = this.retrieveXrds(xrds_location);
          this.logService.logStringMessage('XRDS: ' + xrds);
          this.handleRetrievedXrds(xrds, openid_url);
        } else {
          this.handleDiscoveryResponseHtml(resp, openid_url);
        }
      }
    } else {
      if ((this.finalizeOpenId !== undefined)
          && (this.finalizeOpenId !== null)
          && (typeof (this.finalizeOpenId) == 'function')) {
        // newFinalizeOpenId(url, error)
        this.finalizeOpenId(this.logService, null, "" + req.statusText); 
      } else {
        throw "openid discovery failed!";
      }
    }
  },

  doit : function() {
    var openid_url = this.normalize();

    this.logService.logStringMessage("Checking openid_url: " + openid_url);
    this.discover(openid_url);
  }
};
