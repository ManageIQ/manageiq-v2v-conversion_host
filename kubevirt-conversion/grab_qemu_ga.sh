#!/bin/bash -x
# Define the locations to search inside for "qemu-guest-agent"

declare -A location=(
    ['el6']='http://vault.centos.org/6.9/os/x86_64/Packages/'
    ['el7']='http://vault.centos.org/7.6.1810/os/x86_64/Packages/'
    ['el8']='http://mirror.centos.org/centos-8/8.0.1905/AppStream/x86_64/os/Packages/'
    ['fc28']='http://ftp.fi.muni.cz/pub/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/q/'
    ['lp151']='http://download.opensuse.org/distribution/leap/15.1/repo/oss/x86_64/'
    )
save_dir="/usr/share/virtio-win/linux"

for version in "${!location[@]}"
    do
        mkdir -p $save_dir/$version
        file=$(curl -l "${location[$version]}" 2>/dev/null| grep -Po '(?<=href=")qemu-guest-agent[^"]*.rpm' | head -1)
        curl ${location[$version]}$file -o $save_dir/$version/$file
    done
