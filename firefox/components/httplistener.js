var Cc = Components.classes;
var Ci = Components.interfaces;

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");

var gConsoleService = Cc[ "@mozilla.org/consoleservice;1"].getService(Ci.nsIConsoleService);
var gbLoggingEnabled = false;

var gOpenidListener = [];

const DEFAULT_USER_AGENT = "openinfocard";

function LOG(text)
{
	if(gbLoggingEnabled)
	{
		gConsoleService.logStringMessage(text);
	}
}

const CONTRACT_ID = "@xmldap/httplistener-service;1";
const CLASS_ID = Components.ID("{DC7D00A8-CAFE-11DD-8B0A-5D0156D89593}");
const CLASS_NAME = "HTTP Listener for Openinfocard";

function OICHttpListener() { }

OICHttpListener.prototype = {
  classDescription: CLASS_NAME,  
  classID:          CLASS_ID,
  contractID:       CONTRACT_ID,  
  _xpcom_categories : [ {
    category : "profile-after-change",
    entry : CLASS_NAME,
    value : CONTRACT_ID,
    service : true
  } ],
  QueryInterface: XPCOMUtils.generateQI(
      [Components.interfaces.nsIObserver,
       Components.interfaces.nsIWebProgressListener,
       Components.interfaces.nsISupportsWeakReference,
       Components.interfaces.nsIXULBrowserWindow,
       Components.interfaces.nsISupports]),

  headerName: "User-Agent",
  
  userAgent: DEFAULT_USER_AGENT,
  
  addOpenidListener : function(listener) {
	//LOG("typeof(listener.registerSetupUrl)=" + typeof(listener.registerSetupUrl));
	//LOG("typeof(listener.registerOpenId)=" + typeof(listener.registerOpenId));
	gOpenidListener.push(listener);
  },

  removeOpenidListener : function(listener) {
	  try {
		  delete gOpenidListener[listener];
	  } catch (e) {
		  LOG("removeOpenidListener: Exception=" + e);
	  }
  },

  onLinkIconAvailable : function(aHref)
  {
	LOG("onLinkIconAvailable" + aHref);
  },
  
  _notifySetupUrlListener : function(url) {
	  var func = function(element){
		  try { element.registerSetupUrl(url); } catch (e) {LOG("_notifySetupUrlListener exception=" + e);}};
	  gOpenidListener.forEach(func);
  },
  
  _notifyIdListener : function(url) {
	  var func = function(element){
		  try { element.registerOpenId(url); } catch (e) {LOG("_notifyIdListener exception=" + e);}};
	  gOpenidListener.forEach(func);
  },
  
  onProgressChange : function (aWebProgress, aRequest,
          aCurSelfProgress, aMaxSelfProgress,
          aCurTotalProgress, aMaxTotalProgress)
  {
	  LOG("onProgressChange");
  },

  onStateChange : function(aWebProgress, aRequest, aStateFlags, aStatus)
  {
	  LOG("onStateChange");
  },
  
  onLocationChange : function(aWebProgress, aRequest, aLocation)
  {
	  LOG("onLocationChange: aLocation=" + aLocation);
  },
  
  onStatusChange : function(aWebProgress, aRequest, aStatus, aMessage)
  {
	  LOG("onStatusChange: aMessage=" + aMessage);
  },
  
  onSecurityChange : function(aWebProgress, aRequest, aState)
  {
	  LOG("onSecurityChange");
  },
  
  startDocumentLoad : function(aRequest)
  {
    const nsIChannel = Components.interfaces.nsIChannel;
    var urlStr = aRequest.QueryInterface(nsIChannel).URI.spec;
    LOG("startDocumentLoad: urlStr=" + urlStr);
    var observerService = Components.classes["@mozilla.org/observer-service;1"]
                                    .getService(Components.interfaces.nsIObserverService);
    try {
      observerService.notifyObservers(content, "StartDocumentLoad", urlStr);
    } catch (e) {
    }
  },

  endDocumentLoad : function(aRequest, aStatus)
  {
	    const nsIChannel = Components.interfaces.nsIChannel;
	    var urlStr = aRequest.QueryInterface(nsIChannel).URI.spec;
	    LOG("endDocumentLoad: urlStr=" + urlStr + " aStatus=" + aStatus);
  },
  
	getParam : function(query, param) {
	    var q = query.indexOf('?');
	    if (q > -1) {
	    	query = query.substring(q+1);
	    }
	    var vars = query.split("&");
	    for (var i=0;i<vars.length;i++) {
	        var pair = vars[i].split("=");
	        if (pair[0] == param) {
	            return pair[1];
	        }
	    }
	    return null;
	},

  observe: function(subject, topic, data)
  {
	  var httpChannel;
      if (topic == "http-on-modify-request") {

          httpChannel = subject.QueryInterface(Ci.nsIHttpChannel);
          
          LOG("----------------------------> observed http-on-modify-request: " + httpChannel.URI.asciiSpec);

          var strUA = httpChannel.getRequestHeader(this.headerName);
          if(strUA && strUA.length > 0) {
        	  if(strUA.indexOf(this.userAgent) != -1) {
        		  return;
			  }
				
			  strUA += " ";
		  }
		  strUA += this.userAgent;
    		
          httpChannel.setRequestHeader(this.headerName, strUA, false);
          
          return;
      }

      if (topic == "http-on-examine-response") {
    	  httpChannel = subject.QueryInterface(Ci.nsIHttpChannel);
    	  var url = httpChannel.URI.asciiSpec;
    	  
    	  LOG("----------------------------> observed http-on-examine-response: " + url);
    	  
    	  var openid_mode=this.getParam(url, "openid.mode");

    	  var identity = this.getParam(url, "openid.identity");
    	  if (identity !== null) {
//    		  LOG("----------------------------> observed openid.mode=" + openid_mode + " openid.identity: " + identity);
//	    	  var observerService = Components.classes["@mozilla.org/observer-service;1"]
//	    	                                             .getService(Components.interfaces.nsIObserverService);
//	    	  try {
//	           observerService.notifyObservers(content, "openid.identity", url);
//	         } catch (e) {}
    		 this._notifyIdListener(url);
    		 return;
    	  }
    	  
    	  var user_setup_url = this.getParam(url, "openid.user_setup_url");
    	  if ((openid_mode == "setup_needed") && (user_setup_url !== null)) {
    		  LOG("----------------------------> observed openid.mode=" + openid_mode + " openid.user_setup_url=" + user_setup_url);
    		 this._notifySetupUrlListener(url);
    		 return;
    	  } else {
    		  LOG("############################> observed openid.mode=" + openid_mode + " openid.user_setup_url=" + user_setup_url);
    	  }
    	  
    	  return;
      }

      if (topic == "profile-after-change") {

          LOG("----------------------------> profile-after-change");
          
          var os = Cc["@mozilla.org/observer-service;1"].getService(Ci.nsIObserverService);
          os.addObserver(this, "http-on-modify-request", false);
          os.addObserver(this, "http-on-examine-response", false);
          
          return;
      }
  },
  
  QueryInterface: function (iid) {
        if (iid.equals(Ci.nsIObserver) ||
                iid.equals(Ci.nsISupports) ||
                iid.equals(Ci.nsIOpenIDListener)) {
            return this;
        }
        Components.returnCode = Components.results.NS_ERROR_NO_INTERFACE;
        return null;
    }
};

/**
* XPCOMUtils.generateNSGetFactory was introduced in Mozilla 2 (Firefox 4).
* XPCOMUtils.generateNSGetModule is for Mozilla 1.9.2 (Firefox 3.6).
*/
if (XPCOMUtils.generateNSGetFactory) {
  var NSGetFactory = XPCOMUtils.generateNSGetFactory([OICHttpListener]);
} else {
  var NSGetModule = XPCOMUtils.generateNSGetModule([OICHttpListener]);
}
