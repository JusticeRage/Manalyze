rule BitcoinAddress
{
    meta:
        description = "Contains a valid Bitcoin address"
        author = "Didier Stevens (@DidierStevens)"
    strings:
		$btc = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,33}\b/
    condition:
        any of them
}