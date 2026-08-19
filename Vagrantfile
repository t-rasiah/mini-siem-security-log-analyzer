Vagrant.configure("2") do |config|

  # ============================================
  # Gemeinsame Konfiguration
  # ============================================

  # Debian als Basisbetriebssystem
  config.vm.box = "debian/bookworm64"


  # ============================================
  # VM 1: Mini-SIEM Server
  # ============================================

  config.vm.define "mini-siem" do |siem|

    siem.vm.hostname = "mini-siem"

    # Internes Lab-Netzwerk
    siem.vm.network "private_network",
      ip: "192.168.56.10"

    # VirtualBox Ressourcen
    siem.vm.provider "virtualbox" do |vb|
      vb.name = "mini-siem"
      vb.memory = 2048
      vb.cpus = 2
    end

  end


  # ============================================
  # VM 2: Log Client
  # ============================================

  config.vm.define "log-client" do |client|

    client.vm.hostname = "log-client"

    # Internes Lab-Netzwerk
    client.vm.network "private_network",
      ip: "192.168.56.20"

    # VirtualBox Ressourcen
    client.vm.provider "virtualbox" do |vb|
      vb.name = "log-client"
      vb.memory = 1024
      vb.cpus = 1
    end

  end

end