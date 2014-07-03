/*
    This file is part of Spike Guard.

    Spike Guard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Spike Guard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Spike Guard.  If not, see <http://www.gnu.org/licenses/>.
*/

// TODO: Add AV process names!

rule SysInternals_Names
{
    meta:
        description = "Contains references to SysIntenal's tools."
    strings:
        $a0 = "procexp.exe" nocase wide ascii
        $a1 = "procmon.exe" nocase wide ascii
        $a2 = "netmon.exe" nocase wide ascii
        $a3 = "regmon.exe" nocase wide ascii
        $a4 = "filemon.exe" nocase wide ascii

    condition:
        any of them
}

rule Wireshark_name
{
    meta:
        description = "Contains references to Wireshark."
    strings:
        $a0 = "wireshark.exe" nocase wide ascii
    condition:
        $a0
}

rule VM_Generic_Detection : AntiVM
{
    meta:
        description = "Tries to detect virtualized environments."
    strings:
        $a0 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
        $a1 = "HARDWARE\\Description\\System" nocase wide ascii
        $redpill = {0F 01 0D 00 00 00 00 C3} // Copied from the Cuckoo project
    condition:
        any of them
}

rule VMWare_Detection : AntiVM
{
    meta:
        description = "Looks for VMWare presence."
        origin = "Rules copied from the Cuckoo project."

    strings:
        $a0 = "VMXh"
        $a1 = "vmware" nocase wide ascii
        $vmware4 = "hgfs.sys" nocase wide ascii
        $vmware5 = "mhgfs.sys" nocase wide ascii
        $vmware6 = "prleth.sys" nocase wide ascii
        $vmware7 = "prlfs.sys" nocase wide ascii
        $vmware8 = "prlmouse.sys" nocase wide ascii
        $vmware9 = "prlvideo.sys" nocase wide ascii
        $vmware10 = "prl_pv32.sys" nocase wide ascii
        $vmware11 = "vpc-s3.sys" nocase wide ascii
        $vmware12 = "vmsrvc.sys" nocase wide ascii
        $vmware13 = "vmx86.sys" nocase wide ascii
        $vmware14 = "vmnet.sys" nocase wide ascii
        $vmware15 = "vmicheartbeat" nocase wide ascii
        $vmware16 = "vmicvss" nocase wide ascii
        $vmware17 = "vmicshutdown" nocase wide ascii
        $vmware18 = "vmicexchange" nocase wide ascii
        $vmware19 = "vmdebug" nocase wide ascii
        $vmware20 = "vmmouse" nocase wide ascii
        $vmware21 = "vmtools" nocase wide ascii
        $vmware22 = "VMMEMCTL" nocase wide ascii
        $vmware23 = "vmx86" nocase wide ascii

        // VMware MAC addresses
        $vmware_mac_1a = "00-05-69" wide ascii
        $vmware_mac_1b = "00:05:69" wide ascii
        $vmware_mac_1c = "000569" wide ascii
        $vmware_mac_2a = "00-50-56" wide ascii
        $vmware_mac_2b = "00:50:56" wide ascii
        $vmware_mac_2c = "005056" wide ascii
        $vmware_mac_3a = "00-0C-29" nocase wide ascii
        $vmware_mac_3b = "00:0C:29" nocase wide ascii
        $vmware_mac_3c = "000C29" nocase wide ascii
        $vmware_mac_4a = "00-1C-14" nocase wide ascii
        $vmware_mac_4b = "00:1C:14" nocase wide ascii
        $vmware_mac_4c = "001C14" nocase wide ascii
    condition:
        any of them
}

rule VirtualPC_Detection : AntiVM
{
    meta:
        description = "Looks for VirtualPC presence."
        origin = "Rules copied from the Cuckoo project."
    strings:
        $a0 = {0F 3F 07 0B }
        $virtualpc1 = "vpcbus" nocase wide ascii
        $virtualpc2 = "vpc-s3" nocase wide ascii
        $virtualpc3 = "vpcuhub" nocase wide ascii
        $virtualpc4 = "msvmmouf" nocase wide ascii
    condition:
        any of them
}

rule VirtualBox_Detection : AntiVM
{
    meta:
        description = "Looks for VirtualBox presence."
        origin = "Rules copied from the Cuckoo project."
    strings:
        $virtualbox1 = "VBoxHook.dll" nocase wide ascii
        $virtualbox2 = "VBoxService" nocase wide ascii
        $virtualbox3 = "VBoxTray" nocase wide ascii
        $virtualbox4 = "VBoxMouse" nocase wide ascii
        $virtualbox5 = "VBoxGuest" nocase wide ascii
        $virtualbox6 = "VBoxSF" nocase wide ascii
        $virtualbox7 = "VBoxGuestAdditions" nocase wide ascii
        $virtualbox8 = "VBOX HARDDISK" nocase wide ascii
        $virtualbox9 = "vboxservice" nocase wide ascii
        $virtualbox10 = "vboxtray" nocase wide ascii

        // MAC addresses
        $virtualbox_mac_1a = "08-00-27"
        $virtualbox_mac_1b = "08:00:27"
        $virtualbox_mac_1c = "080027"
    condition:
        any of them
}

rule Parallels_Detection : AntiVM
{
    meta:
        description = "Looks for Parallels presence."
    strings:
        $a0 = "magi"
        $a1 = "c!nu"
        $a2 = "mber"
    condition:
        all of them
}

rule Qemu_Detection : AntiVM
{
    meta:
        description = "Looks for Qemu presence."
    strings:
        $a0 = "qemu" nocase wide ascii
    condition:
        any of them
}

rule Dropper_Strings
{
    meta:
        description = "May have dropper capabilities."
    strings:
        $a0 = "CurrentVersion\\Run" nocase wide ascii
        $a1 = "CurrentControlSet\\Services" nocase wide ascii
        $a2 = "Programs\\Startup" nocase wide ascii
        $a3 = "%temp%" nocase wide ascii
        $a4 = "%allusersprofile%" nocase wide ascii
    condition:
        any of them
}

rule AutoIT_compiled_script
{
    meta:
        description = "Is an AutoIT compiled script."
    strings:
        $a0 = "AutoIt Error" ascii wide
        $a1 = "reserved for AutoIt internal use" ascii wide
    condition:
        any of them
}

rule Misc_Suspicious_Strings
{
    meta:
        description = "Miscellaneous malware strings."
    strings:
        $a0 = "backdoor" nocase ascii wide
        $a1 = "virus" nocase ascii wide
        $a2 = "hack" nocase ascii wide
        $a3 = "exploit" nocase ascii wide
        $a4 = "cmd.exe" nocase ascii wide
    condition:
        any of them
}
