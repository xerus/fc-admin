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

function FleetCommanderSpiceClient(host, port, error_cb, timeout) {
  var self = this;

  this.conn_timeout = timeout || 15000; //ms

  this.sc;
  this.connecting = null;
  this.noretry = false;

  this.stop =  function () {
    if (self.sc) self.sc.stop();
  }

  this.set_connection_timeout = function() {
    if (!self.connecting) {
      self.connecting = setTimeout(function() {
        if (self.sc) self.sc.stop()
        $('#spice-screen').html('');
        self.connecting = null;
        self.noretry = true;
        DEBUG > 0 && console.log('FC: Connection tries timed out');
        $('#spinner-modal').modal('hide');
        showMessageDialog(_('Connection error to virtual machine.'), _('Connection error'));
      }, self.conn_timeout);
    }
  }

  this.spice_connected = function() {
    DEBUG > 0 && console.log('FC: Connected to virtual machine using SPICE');
    $('#spinner-modal').modal('hide');
    if (self.connecting) {
      clearTimeout(self.connecting);
      self.connecting = null;
    }
  }

  this.spice_error = function(err) {
    DEBUG > 0 && console.log('FC: SPICE connection error:', err.message);

    fc.IsSessionActive('', function(resp){
      DEBUG > 0 && console.log('FC: Current session active status:', resp);
      if (resp) {
        self.set_connection_timeout()
        if (err.message == 'Unexpected close while ready' ||
            err.message == 'Connection timed out.' ||
            self.sc.state != 'ready')  {
          if (!self.noretry) {
            $('#spinner-modal h4').text(
              'Connecting to virtual machine. Please wait...');
            $('#spinner-modal').modal('show');
            self.do_connection();
          }
          return
        } else {
          showMessageDialog(
            'Connection error to virtual machine', 'Connection error');
        }
      } else {
        showMessageDialog(
          'Virtual machine has been stopped', 'Connection error');
      }

      $('#spinner-modal').modal('hide');
      if (self.connecting) {
        clearTimeout(self.connecting);
        self.connecting = null;
      }

    });
  }

  this.do_connection = function() {
    DEBUG > 0 && console.log('FC: Connecting to spice session')

    var query = window.btoa(JSON.stringify({
      payload: 'stream',
      protocol: 'binary',
      address: location.hostname,
      port: port,
      binary: 'raw',
    }));

    var cockpit_uri = 'ws://' + location.hostname + ':' + location.port + '/cockpit/channel/' + cockpit.transport.csrf_token + '?' + query

    if (self.sc) self.sc.stop()
    $('#spice-screen').html('');

    self.sc = new SpiceMainConn({
      uri: cockpit_uri, // 'ws://' + location.hostname + ':' + port,
      screen_id: 'spice-screen',
      onsuccess: self.spice_connected,
      onerror: self.spice_error
    });
  }

  try {
    this.do_connection();
  } catch (e) {
    console.error('FC: Fatal error:' + e.toString());
    if (error_cb) error_cb();
  }

}
