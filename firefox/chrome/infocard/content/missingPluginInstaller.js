
//Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService).logStringMessage("typeof(missingPluginInstaller)="+typeof(missingPluginInstaller));
if (typeof(missingPluginInstaller) !== "undefined") {
  // store the original
  missingPluginInstaller.prototype.__newMissingPlugin = missingPluginInstaller.prototype.newMissingPlugin;
  
  missingPluginInstaller.prototype.newMissingPlugin = function(aEvent){
  	var pluginInfo = getPluginInfo(aEvent.target);
  	if ("application/x-informationcard" == pluginInfo.mimetype) {
  		var doc = aEvent.target.ownerDocument;
  		var objElem = aEvent.target;
  		// send event
  		var event = doc.createEvent( "Event");
          event.initEvent( "ICObjectLoaded", true, true);
          objElem.dispatchEvent( event);
  		return;
  	}
  	missingPluginInstaller.prototype.__newMissingPlugin(aEvent);
  };
} else {
  
  //Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService).logStringMessage("typeof(gMissingPluginInstaller)="+typeof(gMissingPluginInstaller));
  if (gBrowser) {
    gBrowser.addEventListener("PluginNotFound", 
        function(aEvent){
          var pluginInfo = getPluginInfo(aEvent.target);
          if ("application/x-informationcard" == pluginInfo.mimetype) {
            var doc = aEvent.target.ownerDocument;
            var objElem = aEvent.target;
            // send event
            var event = doc.createEvent( "Event");
                event.initEvent( "ICObjectLoaded", true, true);
                objElem.dispatchEvent( event);
            return;
          }
        }, 
        true);
  }
}
if (gPluginHandler) {
  if (gBrowser) {
    gBrowser.removeEventListener("PluginNotFound", gPluginHandler, true);
    gBrowser.addEventListener("PluginNotFound", 
        function(aEvent){
          var pluginInfo = getPluginInfo(aEvent.target);
          if ("application/x-informationcard" == pluginInfo.mimetype) {
            var doc = aEvent.target.ownerDocument;
            var objElem = aEvent.target;
            // send event
            var event = doc.createEvent( "Event");
            event.initEvent( "ICObjectLoaded", true, true);
            objElem.dispatchEvent( event);
            return;
          } else {
            gPluginHandler.handleEvent(aEvent);
          }
        }, 
        true);
  }
}