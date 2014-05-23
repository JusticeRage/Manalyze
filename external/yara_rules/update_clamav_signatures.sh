#!/bin/bash

wget http://db.local.clamav.net/main.cvd # Download latest ClamAV rules.
sigtool -u main.cvd # Unpack ClamAV rules
python clamav_to_yara.py -f main.ndb -o clamav.yara # Convert ClamAV rules to Yara
rm main.db main.hdb main.mdb main.fp main.info main.ndb main.zmd main.cvd* # Delete ClamAV artifacts
rm ../../external/yara_rules/clamav.yarac # Delete previously compiled yara rules
cp clamav.yara ../../bin/yara_rules # Replace old yara rules
