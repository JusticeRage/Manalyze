rule APT1_custom_base64_alphabet
{
    meta:
        signature = "APT1's custom base64 alphabet"
        author = "JusticeRage"
    strings:
        $a0 = "oWXYZabcdefghijkl123456789ABCDEFGHIJKL+/MNOPQRSTUVmn0pqrstuvwxyz" wide ascii
    condition:
        $a0
}

rule APT30_UA_Typo
{
    meta:
        signature = "APT30's typo in a user agent"
        author = "JusticeRage"
    strings:
        $a0 = "Moziea/4.0" nocase wide ascii
    condition:
        $a0
}

rule Animal_Farm_Typo
{
    meta:
	signature = "Animal Farm's Typo in a user agent"
        author = "JusticeRage"
    strings:
        $a0 = "Mozilla/4.0 (compatible; MSI 6.0;" nocase wide ascii
    condition:
        $a0
}
