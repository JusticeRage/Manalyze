rule APT1_custom_base64_alphabet
{
    meta:
        signature = "APT1's custom base64 alphabet"
    strings:
        $a0 = "oWXYZabcdefghijkl123456789ABCDEFGHIJKL+/MNOPQRSTUVmn0pqrstuvwxyz"
    condition:
        $a0
}
