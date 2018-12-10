#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Manalyzer output to ATT&CK mapping
# Created by Ronan Mouchoux, Daniel Creus and Ivan Kwiatkowski for BotConf 2018.
#
# Usage: manalyze -p all -o json ... | ./attack.py

import json
import re
import sys
from collections import OrderedDict

mapping = {
    # Plugin Imports
    "Code injection capabilities":                          [("Defense Evasion", "Process Injection")],
    "Code injection capabilities (process hollowing)":      [("Defense Evasion", "Process Injection"),
                                                             ("Defense Evasion", "Process Hollowing")],
    "Manipulates other processes":                          [("Discovery", "Process Discovery"),
                                                             ("Defense Evasion", "Process Injection")],
    "Code injection capabilities (PowerLoader)":            [("Defense Evasion", "Extra Window Memory Injection"),
                                                             ("Defense Evasion", "Process Injection")],
    "Code injection capabilities (process doppelganging)":  [("Defense Evasion", "Process Doppelgänging"),
                                                             ("Defense Evasion", "Process Injection")],
    "Possibly attempts GINA replacement":                   [("Persistence", "Winlogon Helper DLL"),
                                                             ("Defense Evasion", "Process Injection")],
    "Uses functions commonly found in keyloggers":          [("Credential Access", "Input Prompt")],
    "Functions related to the privilege level":             [("Defense Evasion", "Access Token Manipulation")],
    "Deletes entries from the event log":                   [("Defense Evasion", "Indicator Removal on Host")],
    "Functions which can be used for anti-debugging purposes":
                                                            [("Technical Weakness Identification", "Research visibility gap of security vendors")],
    "Memory manipulation functions often used by packers":  [("Defense Evasion", "Software Packing")],
    "Leverages the raw socket API to access the Internet":  [("Build Capabilities", "C2 protocol development")],
    "Interacts with services":                              [("Discovery", "System Service Discovery"),
                                                             ("Execution", "Service Execution")],
    "Enumerates drivers present on the system":             [("Discovery", "System Information Discovery")],
    "Changes object ACLs":                                  [("Defense Evasion", "File Permissions Modification")],
    "Can take screenshots":                                 [("Collection", "Screen Capture")],
    "Can use the microphone to record audio":               [("Collection", "Audio Capture")],
    "Modifies the network configuration":                   [("Discovery", "System Network Configuration Discovery")],
    "Interacts with the certificate store":                 [("Defense Evasion", "Install Root Certificate")],
    "[!] The program may be hiding some of its imports":    [("Defense Evasion", "Obfuscated Files or Information")],
    "Can access the registry":                              [("Discovery", "Query Registry"),
                                                             ("Defense Evasion", "Modify Registry")],
    "Possibly launches other programs":                     [("Execution", "Execution through API")],
    "Uses Microsoft's cryptographic API":                   [("Adversary OPSEC", "Obfuscation or cryptography")],
    "Enumerates local disk drives":                         [("Discovery", "System Information Discovery")],
    "Reads the contents of the clipboard":                  [("Collection", "Clipboard Data")],
    "Checks if it has admin rights":                        [("Discovery", "System Owner/User Discovery")],

    # Plugin Overlay
    "[0-9]+ bytes of data starting at offset 0x[0-9]+":     [("Defense Evasion", "Obfuscated Files or Information")],
    "The overlay data has an entropy of [0-9.]+ and is possibly compressed or encrypted":
                                                            [("Defense Evasion", "Binary Padding"),
                                                             ("Exfiltration", "Data Encrypted"),
                                                             ("Adversary OPSEC", "Obfuscation or cryptography")],

    # Plugin Packer
    "The RICH header checksum is invalid":                  [("Defense Evasion", "Software Packing"),
                                                             ("Defense Evasion", "Masquerading"),
                                                             ("Adversary OPSEC", "Obfuscation or cryptography")],
    "Defense Evasion":                                      [("Defense Evasion", "Software Packing"),
                                                             ("Defense Evasion", "Masquerading"),
                                                             ("Adversary OPSEC", "Obfuscation or cryptography")],
    "Unusual section name found: ":                         [("Defense Evasion", "Software Packing"),
                                                             ("Adversary OPSEC", "Obfuscation or cryptography")],
    "Section [^ ]* is both writable and executable":
                                                            [("Defense Evasion", "Software Packing")],
    "Section [^ ]* has an unusually high entropy (X)":      [("Defense Evasion", "Software Packing"),
                                                             ("Adversary OPSEC", "Obfuscation or cryptography")],
    "The PE only has [0-9]+ import(s)":                     [("Defense Evasion", "Software Packing")],
    "The PE's resources are bigger than it is":             [("Defense Evasion", "Software Packing"),
                                                             ("Adversary OPSEC", "Obfuscation or cryptography")],

    # Plugin Resources
    "Resource [^ ]* detected as a PDF document":            [("Initial Access", "Spearphishing Attachment")],
    "The resource timestamps differ from the PE header":    [("Defense Evasion", "Timestomp"),
                                                             ("Adversary OPSEC", "Obfuscation or cryptography")],
    "Resource [resource name] is possibly compressed or encrypted.":
                                                            [("Defense Evasion", "Software Packing"),
                                                             ("Adversary OPSEC", "Obfuscation or cryptography")],

    # Plugin Suspicious Strings
    "Contains references to system / monitoring tools":     [("Defense Evasion", "Trusted Developer Utilities")],
    "Contains references to internet browsers":             [("Discovery", "System Information Discovery")],
    "Contains references to debugging or reversing tools":  [("Defense Evasion", "Trusted Developer Utilities"),
                                                             ("Technical Weakness Identification", "Research visibility gap of security vendors")],
    "Contains references to security software":             [("Defense Evasion", "Trusted Developer Utilities"),
                                                             ("Technical Weakness Identification", "Research visibility gap of security vendors")],
    "Tries to detect virtualized environments":             [("Defense Evasion", "Trusted Developer Utilities"),
                                                             ("Technical Weakness Identification", "Research visibility gap of security vendors")],
    "Looks for [A-Za-z]+ presence":                         [("Defense Evasion", "Trusted Developer Utilities"),
                                                             ("Technical Weakness Identification", "Research visibility gap of security vendors")],
    "May have dropper capabilities":                        [("Persistence", "Registry Run Keys / Startup Folder")],
    "Is an AutoIT compiled script":                         [("Execution", "Scripting")],
    "Accesses the WMI":                                     [("Execution", "Windows Management Instrumentation")],
    "Contains obfuscated function names":                   [("Defense Evasion", "Obfuscated Files or Information"),
                                                             ("Defense Evasion", "Deobfuscate/Decode Files or Information"),
                                                             ("Adversary OPSEC", "Obfuscation or cryptography"),
                                                             ("Adversary OPSEC", "Obfuscate or encrypt code")],
    "Contains a XORed PE executable":                       [("Defense Evasion", "Obfuscated Files or Information"),
                                                             ("Defense Evasion", "Deobfuscate/Decode Files or Information"),
                                                             ("Adversary OPSEC", "Obfuscation or cryptography"),
                                                             ("Adversary OPSEC", "Obfuscate or encrypt code")],
    "Contains a base64-encoded executable":                 [("Defense Evasion", "Obfuscated Files or Information"),
                                                             ("Defense Evasion", "Deobfuscate/Decode Files or Information"),
                                                             ("Adversary OPSEC", "Obfuscation or cryptography"),
                                                             ("Adversary OPSEC", "Obfuscate or encrypt code")],
    "References the BITS service":                          [("Defense Evasion", "BITS Jobs")],
    "Contains references to mining pools":                  [("Adversary OPSEC", "Non-traditional or less attributable payment options")],

    # Plugin Findcrypt
    "Cryptographic algorithms detected in the binary":      [("Adversary OPSEC", "Obfuscate or encrypt code")],
    "Libraries used to perform cryptographic operations":   [("Adversary OPSEC", "Obfuscate or encrypt code")],

    # Plugin CryptoAddress
    "Contains a valid (Bitcoin|Monero) address":            [("Adversary OPSEC", "Non-traditional or less attributable payment options")],

    # Plugin authenticode
    "The PE's digital signature has been explicitly blacklisted.":
                                                            [("Initial Access", "Supply Chain Compromise")],
    "The PE's digital signature is invalid.":               [("Initial Access", "Supply Chain Compromise")],
    "The PE's certificate was explicitly revoked by its issuer.":
                                                            [("Initial Access", "Supply Chain Compromise")],
    "The file was modified after it was signed.":           [("Initial Access", "Supply Chain Compromise")],
    "The PE uses homographs to impersonate a well known company!":
                                                            ("Defense Evasion", "Masquerading"),
    "The PE pretends to be from .*":                        ("Defense Evasion", "Masquerading"),
}


def apply_mapping(report):
    mapped_output = OrderedDict([
        # PRE-ATT&CK
        ("Priority Definition Planning", []),
        ("Priority Definition Direction", []),
        ("Target Selection", []),
        ("Technical Information Gathering", []),
        ("People Information Gathering", []),
        ("Organizational Information Gathering", []),
        ("Technical Weakness Identification", []),
        ("People Weakness Identification", []),
        ("Organizational Weakness Identification", []),
        ("Adversary OPSEC", []),
        ("Establish & Maintain Infrastructure", []),
        ("Persona Development", []),
        ("Build Capabilities", []),
        ("Test Capabilities", []),
        ("Stage Capabilities", []),
        # ATT&CK
        ("Initial Access", []),
        ("Execution", []),
        ("Persistence", []),
        ("Privilege Escalation", []),
        ("Defense Evasion", []),
        ("Credential Access", []),
        ("Discovery", []),
        ("Lateral Movement", []),
        ("Collection", []),
        ("Exfiltration", []),
        ("Command and Control", [])
    ])

    plugins = report[report.keys()[0]]["Plugins"]
    for p in plugins:
        for o in plugins[p]["plugin_output"]:
            for key in mapping:
                if re.match(key, o) or (type(plugins[p]["plugin_output"][o]) is unicode and re.match(key, plugins[p]["plugin_output"][o])):
                    for m in mapping[key]:
                        if not m[1] in mapped_output[m[0]]:  # Do not add the same element twice.
                            mapped_output[m[0]].append(m[1])


    # Remove empty columns.
    empty = [k for k in mapped_output if not mapped_output[k]]
    for k in empty:
        del mapped_output[k]

    return mapped_output


def main():
    # The the input data
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            report = f.read()
    else:
        report = sys.stdin.read()

    report = json.loads(report)
    mapped = apply_mapping(report)
    print json.dumps(mapped, indent=4)


if __name__ == "__main__":
    main()
