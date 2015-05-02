
VBoxManage createvm -name drone0_big -register
VBoxManage modifyvm drone0_big --memory 512 --vram 64 --acpi on --boot1 dvd --nic1 bridged --bridgeadapter1 en1
VBoxManage modifyvm drone0_big --ostype "Linux26_64"
VBoxManage createvdi --filename "/Users/irish/VirtualBox VMs/drone0_big/drone0_big.vdi" --size 10000
VBoxManage storagectl drone0_big --name "IDE Controller" --add ide
VBoxManage modifyvm drone0_big --boot1 dvd --hda "/Users/irish/VirtualBox VMs/drone0_big/drone0_big.vdi" --sata on
VBoxManage storageattach drone0_big --storagectl "IDE Controller" --port 0 --device 0 --type hdd --medium "/Users/irish/VirtualBox VMs/drone0_big/drone0_big.vdi"
VBoxManage storageattach drone0_big --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium "/Users/irish/Development/ScalablePacketAnalysis/mini.iso"
VBoxManage modifyvm drone0_big --dvd "/Users/irish/Development/ScalablePacketAnalysis/mini.iso"

#VBoxManage guestcontrol drone0_big execute "/bin/ls" --username user --password  --wait-stdout
