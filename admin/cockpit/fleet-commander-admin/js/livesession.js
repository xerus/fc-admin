/*
 * Copyright (C) 2014 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the licence, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * Authors: Alberto Ruiz <aruiz@redhat.com>
 *          Oliver Gutiérrez <ogutierrez@redhat.com>
 */

var _ = cockpit.gettext
var fc = null;
var fcsc = null;
var updater = null;
var reviewing = false;

window.alert = function(message) {
  DEBUG > 0 && console.log('FC: Alert message:' + message);
}

function startLiveSession() {
  // Stop any previous session
  stopLiveSession(function(){
    var domain = sessionStorage.getItem("fc.session.domain")
    var admin_host = location.hostname
    fc.SessionStart(domain, admin_host,function(resp){
      if (resp.status) {
        fcsc = new FleetCommanderSpiceClient(
          admin_host, resp.port, stopLiveSession);
        listenForChanges();
      } else {
        showMessageDialog(resp.error, _('Error'));
      }
    })
  });
}

function stopLiveSession(cb) {
  if (fcsc) fcsc.stop();
  fc.SessionStop(function(resp){
    if (typeof(cb) === 'function') {
      cb()
    } else {
      location.href = 'index.html';
    }
  });
}

function listenForChanges() {
  updater = window.setInterval (readChanges, 1000);
}

function readChanges() {
  fc.GetChanges(function(resp){
    if (!reviewing) {
      $('#gsettings-event-list').html('');
      $('#libreoffice-event-list').html('');
      $('#networkmanager-event-list').html('');

      if ('org.libreoffice.registry' in resp)
        populateChanges('#libreoffice-event-list', resp['org.libreoffice.registry']);
      if ('org.gnome.gsettings' in resp)
        populateChanges('#gsettings-event-list', resp['org.gnome.gsettings']);
      if ('org.freedesktop.NetworkManager' in resp)
        populateChanges('#networkmanager-event-list', resp['org.freedesktop.NetworkManager'], true);
    }
  });
}

function populateChanges(section, data, only_value) {
  $.each (data, function (i, item) {
    if (only_value) {
      var row = item[1];
    } else {
      var row = item.join (" ");
    }
    var citem = $($('#change-item-template').html());
    citem.appendTo($(section));
    checkbox = citem.find('input[type=checkbox]');
    checkbox.attr('data-id', item[0]);
    citem.find('.changekey').html(row);
  });
}

function reviewAndSubmit() {
  reviewing = true;
  $('.change-checkbox').show();
  $('#event-logs').modal('show');
}

function deployProfile() {
  var gsettings = [];
  var libreoffice = [];
  var networkmanager = [];

  $.each($('#gsettings-event-list input[data-id]:checked'), function (i,e) {
    gsettings.push($(this).attr('data-id'));
  });

  $.each($('#libreoffice-event-list input[data-id]:checked'), function (i,e) {
    libreoffice.push($(this).attr('data-id'));
  });

  $.each($('#networkmanager-event-list input[data-id]:checked'), function (i,e) {
    networkmanager.push($(this).attr('data-id'));
  });

  var changeset = {
    "org.gnome.gsettings": gsettings,
    "org.libreoffice.registry": libreoffice,
    "org.freedesktop.NetworkManager": networkmanager
  };

  $('#spinner-modal h4').text(_('Saving settings'));
  $('#spinner-modal').modal('show');

  fc.SelectChanges(changeset, function(resp){
    if (resp.status) {
      stopLiveSession(function () {
        var uid = sessionStorage.getItem("fc.session.profile_uid");
        fc.SessionSave(uid, function(){
            if (resp.status) {
              location.href='index.html'
            } else {
              showMessageDialog(_('Error saving session'), _('Error'));
            }
        });
      });
    } else {
      showMessageDialog(_('Error saving settings'), _('Error'));
    }
  });
}

$(document).ready (function () {
  $('#close-live-session').click(stopLiveSession);
  $('#review-changes').click(reviewAndSubmit);
  $('#deploy-profile').click(deployProfile);

  $("#event-logs").on('hidden.bs.modal', function () {
    reviewing = false;
  });

  // Create a Fleet Commander dbus client instance
  fc = new FleetCommanderDbusClient(function(){

    fc.GetDebugLevel(function(resp) {
      setDebugLevel(resp);
    });

    $('#main-container').show();
    startLiveSession();
    // Error catchall to workarount "oops" message in cockpit
    window.onerror = function(message, url, lineNumber) {
      DEBUG > 0 && console.error('Live session error: (', lineNumber, ' ', url, ') ', message);
      return true;
    };
  }, function(){
    $('#main-container').hide()
    showCurtain(
      _('Can not connect with Fleet Commander dbus service'),
      _('Can\'t connect to Fleet Commander'),
      null,
      {
        'dbus-retry': {
          text: 'Retry connection',
          class: 'btn-primary',
          callback: function(){ location.reload() }},
      });
  });

});
