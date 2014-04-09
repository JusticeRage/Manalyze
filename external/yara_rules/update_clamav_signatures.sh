#!/bin/bash

wget http://db.local.clamav.net/main.cvd
sigtool -u main.cvd
python clamav_to_yara.py -f main.ndb -o clamav.yara
rm main.db main.hdb main.mdb main.fp main.info main.ndb main.zmd main.cvd
