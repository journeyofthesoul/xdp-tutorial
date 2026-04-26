BOX_IMAGE = "bento/ubuntu-25.04"
BOX_VERSION = "202510.26.0"

Vagrant.configure("2") do |config|
  config.vm.box = BOX_IMAGE
  config.vm.box_version = BOX_VERSION

  config.vm.define "edge-node" do |node|
    node.vm.hostname = "edge-node"

    node.vm.synced_folder ".", "/vagrant", type: "virtualbox",
                         mount_options: ["dmode=775", "fmode=664"]

    # Private network for testing
    node.vm.network :private_network, ip: "192.168.56.10"

    node.vm.provider "virtualbox" do |vb|
      vb.memory = 4096
      vb.cpus   = 2
    end

    # Provisioning: install eBPF/XDP tooling
    node.vm.provision "shell", inline: <<-SHELL
      set -eux
      export DEBIAN_FRONTEND=noninteractive

      # Work around broken DNS via systemd-resolved in this VM image.
      systemctl disable --now systemd-resolved || true
      rm -f /etc/resolv.conf
      printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" >/etc/resolv.conf

      # Keep iperf3 as an on-demand CLI tool, not a boot daemon.
      echo "iperf3 iperf3/start_daemon boolean false" | debconf-set-selections

      apt-get update

      apt-get install -y \
        clang llvm \
        libbpf-dev \
        libelf-dev \
        gcc make \
        iproute2 \
        linux-tools-common \
        linux-tools-generic \
        tcpdump \
        net-tools \
        git \
        pkg-config \
        libpcap-dev \
        build-essential \
        libc6-dev-armhf-cross m4

      # Install iperf3 for benchmarking
      apt-get install -y iperf3

      # Ensure bpftool is available
      apt-get install -y linux-tools-$(uname -r) || true

      # Install kernel headers for bpftool to work properly
      apt-get install -y linux-headers-generic || true

      # Disable swap (helps consistency)
      swapoff -a
    SHELL

    # Remount /vagrant if VirtualBox auto-mount is missed after boot.
    node.vm.provision "shell", run: "always", inline: <<-SHELL
      set -eux

      # Keep guest clock in sync to avoid make clock-skew warnings.
      timedatectl set-ntp true || true
      systemctl restart systemd-timesyncd || true

      if ! mountpoint -q /vagrant; then
        mount -t vboxsf -o uid=$(id -u vagrant),gid=$(id -g vagrant),dmode=775,fmode=664 vagrant /vagrant || true
      fi
    SHELL
  end
end