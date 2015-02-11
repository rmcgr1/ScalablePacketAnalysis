
VBoxManage createvm -name drone0 -register
VBoxManage modifyvm drone0 --memory 256 --vram 64 --acpi on --boot1 dvd --nic1 bridged --bridgeadapter1 en1
VBoxManage modifyvm drone0 --ostype "Linux26_64"
VBoxManage createvdi --filename "/Users/irish/VirtualBox VMs/drone0/drone0.vdi" --size 5000
VBoxManage storagectl drone0 --name "IDE Controller" --add ide
VBoxManage modifyvm drone0 --boot1 dvd --hda "/Users/irish/VirtualBox VMs/drone0/drone0.vdi" --sata on
VBoxManage storageattach drone0 --storagectl "IDE Controller" --port 0 --device 0 --type hdd --medium "/Us
ers/irish/VirtualBox VMs/drone0/drone0.vdi"
storageattach drone0 --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium
"/Users/irish/Development/ScalablePacketAnalysis/mini.iso"
VBoxManage modifyvm drone0 --dvd "/Users/irish/Development/ScalablePacketAnalysis/mini.iso"

VBoxManage guestcontrol drone0 execute "/bin/ls" --username user --password  --wait-stdout
