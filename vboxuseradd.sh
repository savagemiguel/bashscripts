#!/bin/bash

# Inspired by https://github.com/dnschneid/crouton/wiki/VirtualBox-udev-integration

usbnode_path=$(find / -name VBoxCreateUSBNode.sh 2> /dev/null | head -n 1)
if [[ -z $usbnode_path ]]; then
    echo Warning: VBoxCreateUSBNode.sh not found in the system.
    exit 1
fi

chmod 755 $usbnode_path
chown root:root $usbnode_path

users_gid=$(getent group vboxusers | awk -F: '{printf "%d\n", $3}')

rules="SUBSYSTEM==\"usb_device\", ACTION==\"add\", RUN+=\"$usbnode_path \$major \$minor \$attr{bDeviceClass} $users_gid\"
SUBSYSTEM==\"usb\", ACTION==\"add\", ENV{DEVTYPE}==\"usb_device\", RUN+=\"$usbnode_path \$major \$minor \$attr{bDeviceClass} $users_gid\"
SUBSYSTEM==\"usb_device\", ACTION==\"remove\", RUN+=\"$usbnode_path --remove \$major \$minor\"
SUBSYSTEM==\"usb\", ACTION==\"remove\", ENV{DEVTYPE}==\"usb_device\", RUN+=\"$usbnode_path --remove \$major \$minor\""

echo "$rules" > /etc/udev/rules.d/virtualbox.rules
rm -f /etc/udev/rules.d/*-virtualbox.rules
udevadm control --reload
adduser `logname` vboxusers

echo All done.
echo Please log out and log in again to apply the changes.
echo You may need to restart your PC or linux box for the changes to take effect.