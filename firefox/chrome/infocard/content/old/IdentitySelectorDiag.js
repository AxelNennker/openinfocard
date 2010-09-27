//------------------------------------------------------------------------------
// Desc:
// Tabs: 3
//
// Copyright (c) 2007-2008 Novell, Inc. All Rights Reserved.
//
// This program and the accompanying materials are made available
// under, alternatively, the terms of:  a) the Eclipse Public License v1.0
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

// **************************************************************************
// Desc: Global services
// **************************************************************************

var gConsoleService = Components.classes[ "@mozilla.org/consoleservice;1"].
                        getService( Components.interfaces.nsIConsoleService);
var gbLoggingEnabled = true;
var gDebugMode = true;

// **************************************************************************
// Desc:
// **************************************************************************

var IdentitySelectorDiag =
{
  // ***********************************************************************
  // Method: reportError
  // ***********************************************************************
 
  reportError : function( location, description)
  {
    var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                                   .getService(Components.interfaces.nsIPromptService);
    prompts.alert( null, "IdentitySelector Error: " + location, description);
    IdentitySelectorDiag.logMessage( location, "Error:" + description);
  },

  // ***********************************************************************
  // Method: throwError
  // ***********************************************************************
 
  throwError : function( location, description)
  {
          IdentitySelectorDiag.reportError( location, description);
          throw( "IdentitySelector Exception:" + location + ": " + description);
  },

  // ***********************************************************************
  // Method: logMessage
  // ***********************************************************************
 
  logMessage : function( location, message)
  {
    if( gbLoggingEnabled)
    {
            gConsoleService.logStringMessage( "IdentitySelector:" +
                    location + ": " + message);
    }
  },
     
  // ***********************************************************************
  // Method: debugReportError
  // ***********************************************************************
  debugReportError : function( location, description)
  {
          if( gDebugMode)
          {
            var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                                             .getService(Components.interfaces.nsIPromptService);
            prompts.alert( null, "IdentitySelector Error: " + location, description);
          }
          else
          {
            IdentitySelectorDiag.logMessage( location, "Error:" + description);
          }
  },     
       
// ***********************************************************************
// Method: dumpConsoleToLogFile
// ***********************************************************************
 
  dumpConsoleLogToFile : function( filePath)
  {
    var messageArray = {};
    var messageCount = {};
    var logBuffer = "";
       
    try
    {
            gConsoleService.getMessageArray( messageArray, messageCount);
           
            for( var i = 0; i < messageCount.value; i++)
            {
                    var messageStr = messageArray.value[ i].message;
                   
                    if( messageStr.indexOf( "IdentitySelector:") > -1)
                    {
                            logBuffer += messageStr + "\n";
                    }
            }
           
            if( gbIsMac || gbIsLinux)
            {
                    IdentitySelectorUtil.writeFile( "/tmp/icardxpi.log", logBuffer);
            }
    }
    catch( e)
    {
      IdentitySelectorDiag.reportError( "dumpConsoleLogToFile", e);
    }
},

// ***********************************************************************
// Method: logPlatformInfo
// ***********************************************************************
 
  logPlatformInfo : function()
  {
    try
    {
            IdentitySelectorDiag.logMessage( "logPlatformInfo",
                  "platform = " + navigator.platform);
                 
          IdentitySelectorDiag.logMessage( "logPlatformInfo",
                  "appName = " + navigator.appName);
                 
          IdentitySelectorDiag.logMessage( "logPlatformInfo",
                  "appVersion = " + navigator.appVersion);
                 
          IdentitySelectorDiag.logMessage( "logPlatformInfo",
                  "product = " + navigator.product);
                 
          IdentitySelectorDiag.logMessage( "logPlatformInfo",
                  "productSub = " + navigator.productSub);
                 
          IdentitySelectorDiag.logMessage( "logPlatformInfo",
                  "userAgent = " + navigator.userAgent);
                 
          IdentitySelectorDiag.logMessage( "logPlatformInfo",
                  "oscpu = " + navigator.oscpu);
    }
    catch( e)
    {
    }
  }
};