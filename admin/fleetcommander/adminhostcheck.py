import sys
import os
import stat
import subprocess
import urllib2

ADMIN_HOST_URL = 'http://%s:%s/changes/check/'

mode = sys.argv[1]

# Check libvirt availavility
if mode == 'session':
    virsh_socket = os.path.join(
        os.environ['XDG_RUNTIME_DIR'],
        'libvirt/libvirt-sock')
else:
    virsh_socket = None

virsh_status = subprocess.Popen(
    ['virsh', 'list'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE).wait()

if not stat.S_ISSOCK(os.stat(virsh_socket).st_mode):
    virsh_status = 1

# Check admin host connectivity
host = os.environ['SSH_CLIENT'].split()[0]
port = sys.argv[2]
if len(sys.argv) > 3:
    host = sys.argv[3]

try:
    urllib2.urlopen(ADMIN_HOST_URL % (host, port), None, 5).read()
    admin_host_status = 0
except Exception, e:
    admin_host_status = 1

print('%s %s %s %s' % (virsh_socket, host, virsh_status, admin_host_status))
