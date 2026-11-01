#!/bin/bash
# Build and run the Team 21 SDN lab (L4 load balancer + security) in a
# privileged container.
#
#   ./run.sh build          build the image
#   ./run.sh experiments    full automated evaluation (results/)
#   ./run.sh controller     start the Ryu controller (terminal 1)
#   ./run.sh mininet [mode] start the topology + CLI (terminal 2); sdn|rstp|stp
#   ./run.sh shell          shell in the running demo container
#
# Needs root for Docker and for loading the openvswitch kernel module.
set -euo pipefail
cd "$(dirname "$0")"
IMAGE=lbsec-sdn
NAME=lbsec-sdn
SUDO=""; [[ $EUID -ne 0 ]] && ! docker info >/dev/null 2>&1 && SUDO=sudo

ensure_modules() {
  # Works with or without host sudo: a privileged throwaway container shares
  # the host kernel, so it can load the module when plain modprobe may not.
  $SUDO modprobe openvswitch 2>/dev/null || \
    docker run --rm --privileged -v /lib/modules:/lib/modules:ro \
      --entrypoint /sbin/modprobe "$IMAGE" openvswitch
}

ensure_container() {
  if ! $SUDO docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
    ensure_modules
    $SUDO docker run -d --rm --name "$NAME" --privileged \
      -v /lib/modules:/lib/modules:ro -v "$PWD":/demo \
      -p 8080:8080 "$IMAGE" sleep infinity >/dev/null
    sleep 2
  fi
}

case "${1:-}" in
  build)       $SUDO docker build -t "$IMAGE" . ;;
  experiments) ensure_modules
               $SUDO docker run --rm --privileged -v /lib/modules:/lib/modules:ro \
                 -v "$PWD":/demo "$IMAGE" python3 sim/experiments.py "${@:2}" 2>&1 | tee results/run.log ;;
  controller)  ensure_container
               $SUDO docker exec -it -e PYTHONPATH=/demo "$NAME" ryu-manager \
                 --ofp-tcp-listen-port 6653 controller.app ;;
  mininet)     ensure_container
               $SUDO docker exec -it -e PYTHONPATH=/demo "$NAME" python3 sim/topo.py --mode "${2:-sdn}" ;;
  shell)       ensure_container; $SUDO docker exec -it -e PYTHONPATH=/demo "$NAME" bash ;;
  stop)        $SUDO docker rm -f "$NAME" ;;
  *)           sed -n '2,12p' "$0"; exit 1 ;;
esac
