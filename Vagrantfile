BOX_IMAGE = "bento/ubuntu-25.04"
BOX_VERSION = "202510.26.0"

Vagrant.configure("2") do |config|
  config.vm.box = BOX_IMAGE
  config.vm.box_version = BOX_VERSION

  config.vm.define "edge-node" do |node|
    node.vm.hostname = "edge-node"

    # Private network for testing
    node.vm.network :private_network, ip: "192.168.56.10"

    node.vm.provider "virtualbox" do |vb|
      vb.memory = 4096
      vb.cpus   = 2
    end

    # Provisioning: install eBPF/XDP tooling
    node.vm.provision "shell", inline: <<-SHELL
      set -eux

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
        iperf3 \
        git \
        pkg-config \
        libpcap-dev \
        build-essential \
        libc6-dev-i386 m4

      # Ensure bpftool is available
      apt-get install -y linux-tools-$(uname -r) || true

      # Ensure kernel headers are installed for the running kernel
      apt-get install -y linux-headers-$(uname -r) || true

      # Disable swap (helps consistency)
      swapoff -a
    SHELL
  end
end