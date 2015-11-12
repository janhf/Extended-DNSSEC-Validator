/* ***** BEGIN LICENSE BLOCK *****
 * This file is part of Extended DNSSEC Validator Add-on.
 *
 * Extended DNSSEC Validator Add-on is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Extended DNSSEC Validator Add-on is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * You should have received a copy of the GNU General Public License along with
 * Extended DNSSEC Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK ***** */

/* Utility class to handle manipulations of the dnssec indicators in the UI */
org.os3sec.Extval.UIHandler = {
  
  //Domain is not secured by DNSSEC
  STATE_DOMAIN_UNSECURED                  : "domainUnsecured",
  //Secure denial of existence
  STATE_NXDOMAIN_UNSECURED                : "nxdomainUnsecured",
  //Domain is secured, but domain name does not exist
  STATE_SECURE_NXDOMAIN                   : "secureNxdomain",
  //Domain is secured, invalid signature
  STATE_DOMAIN_BOGUS                      : "domainBogus",
  //Domain is secured, connected address is spoofed
  STATE_SECURE_ADDRESS_SPOOFED            : "secureAddressSpoofed",
  //Domain is secured, remote host verified
  STATE_SECURE_TRANSPORT_INSECURE         : "secureTransportInsecure",
  
  //Domain is secured, cert error
  STATE_CERT_ERROR                        : "certError",
  //Domain is secured, cert validated by DNSSEC
  STATE_CERT_DNSSEC                       : "certDNSSEC",
  //Domain is secured, cert validated by CA
  STATE_CERT_CA                           : "certCA",
  //Domain is secured, cert validated by DNSSEC and CA
  STATE_CERT_DNSSEC_CA                    : "certDNSSEC_CA",
  //Domain is secured, cert invalid by DNSSEC
  STATE_CERT_INVALID_DNSSEC               : "certInvalidDNSSEC",
  
  //Action
  STATE_ACTION : "stateAction",
  // Error or unknown state occured
  STATE_ERROR : "stateError",

  // Cache the most recent uri and state
  _uri : null,
  _state : null,
  
  init : function() {
    this.strings = document.getElementById("extval-strings");
    this.switchHttpsBox = document.getElementById("switch-https-box");
  },

  /*
   * Updates the messages in identity popup when it opens
   */
  onIdentityPopupShow: function(event) {
	  this.updateIdentityPopup(this._state);
  },
  
  /*
   * Handles the button to switch current page to https
   */
  switchHttps: function() {
    org.os3sec.Extval.Extension.logMsg("Locationbar-btn: switching to https");
    window.gBrowser.loadURI(this._uri.spec.replace('http','https'));
  },
  
  /*
   * Enables the switch to https button in location bar
   */
  enableSwitchHttps: function(uri,enable) {
    if(uri != null &&  uri != gBrowser.currentURI) {
      return; //tab is changed
    }
    this.switchHttpsBox.className = enable ? "" : "disabled";
  },
  
  /**
   * Update the UI to reflect the specified state, which should be one of the
   * STATE_* constants.
   */
  setState : function(uri, newState) {
    org.os3sec.Extval.Extension.logMsg("Changing state to: "+newState + "("+ ((uri!=null)?uri:"null") +")");
    
    //stop updating if hostname changed during resolving process (tab has been switched)
    if(uri != null && uri.spec != gBrowser.currentURI.spec) {
	    org.os3sec.Extval.Extension.logMsg("Ignoring setState because current browser tab is different"+gBrowser.currentURI);
    	return;
    }
    
    this._state = newState;
    this._uri = uri;
    this.updateIdentityPopup(newState);
    
    //disable the switch https button
    this.enableSwitchHttps(uri,false);
  },
  
  updateIdentityPopup: function(state) {
    let connection = document.getElementById("identity-popup").getAttribute("connection");
	  
	  if(state == this.STATE_DOMAIN_BOGUS
	      || state == this.STATE_CERT_ERROR
        || state == this.STATE_CERT_INVALID_DNSSEC
    ) {
      connection = "not-secure";
    }
    
    //if(state == this.STATE_CERT_DNSSEC) {
      //Never _ever_declare something as secure! 
      //e.g. not this way...
      ///This will break mixed content detection for example...
      //connection = "secure";
    //}
	  
	  
	  // Update all elements.
    let elementIDs = [
      "identity-popup",
      "identity-popup-securityView-body",
    ];

    function updateAttribute(elem, attr, value) {
      if (value) {
        elem.setAttribute(attr, value);
      } else {
        elem.removeAttribute(attr);
      }
    }

    for (let id of elementIDs) {
      let element = document.getElementById(id);
      updateAttribute(element, "connection", connection);
      updateAttribute(element, "dnssec", this._state);
    }
  }
};
