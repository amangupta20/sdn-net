#!/bin/bash
# Start Open vSwitch (kernel datapath; module must be loaded on the host).
set -e
/usr/share/openvswitch/scripts/ovs-ctl start --system-id=random >/dev/null
export PYTHONPATH=/demo
exec "$@"
