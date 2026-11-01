# Running on macOS

Docker on a Mac is not enough on its own. The demo needs the Linux
`openvswitch` kernel module, and containers use the host's kernel: macOS has
no Linux kernel, and Docker Desktop's hidden VM does not ship that module.
The fix is a real Ubuntu VM, which has a full Linux kernel. Multipass is the
quickest way to get one.

Works on Intel and Apple Silicon (M1/M2/M3) Macs. The Apple Silicon path is
untested: if `build` fails there, check that step first.

## 1. Create the VM (once)

On the Mac, in Terminal:

```bash
brew install --cask multipass
multipass launch 22.04 --name sdn --cpus 2 --memory 4G --disk 20G
multipass transfer sdn-net.tar.gz sdn:
```

No Homebrew? Download Multipass from https://canonical.com/multipass instead.

## 2. Set up inside the VM (once)

```bash
multipass shell sdn
```

You are now in Ubuntu. Then:

```bash
sudo apt update && sudo apt install -y docker.io
tar -xzf sdn-net.tar.gz
cd sdn-net
sudo ./run.sh build          # several minutes
```

## 3. Run the demo

The demo needs two terminals. For each one, open a new Mac Terminal window and
run `multipass shell sdn`, then `cd sdn-net`.

- Terminal 1: `sudo ./run.sh controller`
- Terminal 2: `sudo ./run.sh mininet`

Everything else is as in `README.md`. A third terminal for `sudo ./run.sh shell`
works the same way.

## Stopping and starting

```bash
multipass stop sdn           # on the Mac, when done
multipass start sdn          # next time; no rebuild needed
multipass delete --purge sdn # remove the VM entirely
```

## Getting files out of the VM

```bash
multipass transfer sdn:sdn-net/results/lb.png .
multipass transfer sdn:sdn-net/results/failover.png .
multipass transfer sdn:sdn-net/results/summary.md .
```

Or mount a Mac folder into the VM instead:
`multipass mount ~/sdn-work sdn:/home/ubuntu/sdn-work`.

## Notes

- Timings inside a VM are noisier than on bare Linux. Compare the schemes
  against each other, not against hardware numbers.
- `docker: permission denied` means a missing `sudo`.
- `modprobe: FATAL: Module openvswitch not found` means you are not in the
  Ubuntu VM. Run `multipass shell sdn` first.
