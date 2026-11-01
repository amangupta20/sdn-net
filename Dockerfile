# Ubuntu 22.04: last LTS whose Python (3.10) still runs Ryu 4.34.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        mininet openvswitch-switch openvswitch-common \
        python3 python3-pip python3-networkx python3-matplotlib \
        iperf iputils-ping iproute2 net-tools kmod curl procps tcpdump \
    && rm -rf /var/lib/apt/lists/*
# Ryu 4.34 (unmaintained) needs an old setuptools to build. eventlet 0.33.3
# is the newest that runs on Python 3.10 with Ryu, once Ryu's reference to the
# removed eventlet.wsgi.ALREADY_HANDLED is patched out.
RUN pip3 install --no-cache-dir "setuptools<68" wheel \
 && pip3 install --no-cache-dir --no-build-isolation ryu==4.34 eventlet==0.33.3 \
 && grep -rl ALREADY_HANDLED /usr/local/lib/python3.10/dist-packages/ryu \
    | xargs -r sed -i 's/from eventlet.wsgi import ALREADY_HANDLED/ALREADY_HANDLED = []/' \
 && python3 -c "import ryu.cmd.manager, ryu.app.wsgi, ryu.topology.switches, ryu.lib.ofctl_v1_3" \
 && ryu-manager --version
WORKDIR /demo
COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["bash"]
