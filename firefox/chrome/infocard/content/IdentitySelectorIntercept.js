//------------------------------------------------------------------------------
// Desc:
// Tabs: 3
//
// Copyright (c) 2007-2008 Novell, Inc. All Rights Reserved.
//
// This program and the accompanying materials are made available
// under, alternatively, the terms of:   a) the Eclipse Public License v1.0
// which accompanies this distribution, and is available at
// http://www.eclipse.org/legal/epl-v10.html; or, b) the Apache License,
// Version 2.0 which accompanies this distribution as is available at
// www.opensource.org/licenses/apache2.0.php.
//
// To contact Novell about this file by physical or electronic mail,
// you may find current contact information at www.novell.com.
//
// Author: Andrew Hodgkinson <ahodgkinson@novell.com>
//------------------------------------------------------------------------------

// ***********************************************************************
// Function: interceptOnDOMChanged
// ***********************************************************************
let interceptOnDOMChanged = function( event)
{
  var isMutationEvent = (event instanceof MutationEvent);
  if (!isMutationEvent) return;
  
  var target = event ? event.target : this;

  if( target.wrappedJSObject)
  {
    target = target.wrappedJSObject;
  }

  try
  {
    var doc = target.ownerDocument;
    if(!doc) return;
    var isDocument = ((doc instanceof HTMLDocument) || ((doc instanceof XULDocument)));
    if (!isDocument) return;
    var domEvent = doc.createEvent( "Event");
    domEvent.initEvent( "ICDOMChanged", true, true);
    target.dispatchEvent( domEvent);
  }
  catch( e)
  {
    var debug = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
    debug.logStringMessage("interceptOnDOMChanged: exception=" + e);
  }
};
       
       

// **************************************************************************
// Desc: Configure the identity selector context object
// **************************************************************************
try
{
  var debug = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);

  if( this.__identityselector__ === undefined)
  {
    this.__identityselector__ = {};
    this.__identityselector__.data = {};
    this.__identityselector__.submitIntercepted = false;
 
    // Insert ourselves into the submit handler chain
   
    this.__identityselector__.chainSubmit =
            HTMLFormElement.prototype.submit;

    HTMLFormElement.prototype.submit = function()
    {
      try {
        var event = document.createEvent( "Event");
        event.initEvent( "ICFormSubmit", true, true);
        this.dispatchEvent( event);
//        if (document.__identityselector__.submitIntercepted === false) {
//          document.__identityselector__.submitIntercepted = true;
          document.__identityselector__.chainSubmit.apply( this);
//        }
      } catch (submitException) {
        alert("submit: exception=" + submitException);
      }
    };
   
    // Define a value getter
   
    this.__identityselector__.valueGetter = function()
    {
      try
      {
        var event = document.createEvent( "Event");
        event.initEvent( "ICGetTokenValue", true, true);
        this.dispatchEvent( event);
        return( this.__value);
      }
      catch( e)
      {
        alert( e);
      }
      return null;
    };
   
    // Special case for Microsoft sites (such as live.com) that
    // expect a cardspace object to be available
   
    cardspace = {};
    cardspace.__defineGetter__( "value", function()
    {
      try
      {
        if( document.__identityselector__.targetElem === undefined)
        {
          var event = document.createEvent( "Event");
          event.initEvent( "ICProcessItems", true, true);
          document.dispatchEvent( event);
        }
   
        return( document.__identityselector__.targetElem.value);
      }
      catch( e)
      {
        alert( e);
      }
      return null;
    });

    // Add DOM listeners to watch for changes to the document
    // that could result in new information card objects being
    // added
   
    this.addEventListener(
            "DOMNodeInserted",
            interceptOnDOMChanged,
            false, false);
   
    this.addEventListener(
            "DOMAttrModified",
            interceptOnDOMChanged,
            false, false);
   
    this.addEventListener(
            "DOMSubtreeModified",
            interceptOnDOMChanged,
            false, false);
   
    this.addEventListener(
            "DOMNodeInsertedIntoDocument",
            interceptOnDOMChanged,
            false, false);
  }
}
catch( e)
{
  var debug = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
  debug.logStringMessage("intercept: exception=" + e);
}