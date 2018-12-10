rule MoneroAddress
{
    meta:
        description = "Contains a valid Monero address"
        author = "Emilien LE JAMTEL (@__Emilien__)"
    strings:
		$monero = /\b4[0-9AB][0-9a-zA-Z]{93}|4[0-9AB][0-9a-zA-Z]{104}\b/
    condition:
        any of them
}
