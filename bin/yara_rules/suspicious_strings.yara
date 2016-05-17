/*
    This file is part of Manalyze.

    Manalyze is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Manalyze is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Manalyze.  If not, see <http://www.gnu.org/licenses/>.
*/

rule System_Tools
{
    meta:
        description = "Contains references to system / monitoring tools"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = "wireshark.exe" nocase wide ascii
        $a1 = "ethereal.exe" nocase wide ascii
        $a2 = "netstat.exe" nocase wide ascii
        $a3 = /taskm(an|gr|on).exe/ nocase wide ascii
        $a4 = /regedit(32)?.exe/ nocase wide ascii
        $a5 = "sc.exe" nocase wide ascii
        $a6 = "procexp.exe" nocase wide ascii
        $a7 = "procmon.exe" nocase wide ascii
        $a8 = "netmon.exe" nocase wide ascii
        $a9 = "regmon.exe" nocase wide ascii
        $a10 = "filemon.exe" nocase wide ascii
        $a11 = "msconfig.exe" nocase wide ascii
    condition:
        any of them
}

rule Browsers
{
    meta:
        description = "Contains references to internet browsers"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $ie = "iexplore.exe" nocase wide ascii
        $ff = "firefox.exe" nocase wide ascii
        $ff_key = "key3.db"
        $ff_log = "signons.sqlite"
        $chrome = "chrome.exe" nocase wide ascii
		// TODO: Add user-agent strings
    condition:
        any of them
}

rule RE_Tools
{
    meta:
        description = "Contains references to debugging or reversing tools"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = /ida(q)?(64)?.exe/ nocase wide ascii
        $a1 = "ImmunityDebugger.exe" nocase wide ascii
        $a2 = "ollydbg.exe" nocase wide ascii
        $a3 = "lordpe.exe" nocase wide ascii
        $a4 = "peid.exe" nocase wide ascii
        $a5 = "windbg.exe" nocase wide ascii
    condition:
        any of them
}

rule Antivirus
{
    meta:
        description = "Contains references to security software"
        author = "Jerome Athias"
        source = "Metasploit's killav.rb script"

    strings:
        $a0 = "AAWTray.exe" nocase wide ascii
        $a1 = "Ad-Aware.exe" nocase wide ascii
        $a2 = "MSASCui.exe" nocase wide ascii
        $a3 = "_avp32.exe" nocase wide ascii
        $a4 = "_avpcc.exe" nocase wide ascii
        $a5 = "_avpm.exe" nocase wide ascii
        $a6 = "aAvgApi.exe" nocase wide ascii
        $a7 = "ackwin32.exe" nocase wide ascii
        $a8 = "adaware.exe" nocase wide ascii
        $a9 = "advxdwin.exe" nocase wide ascii
        $a10 = "agentsvr.exe" nocase wide ascii
        $a11 = "agentw.exe" nocase wide ascii
        $a12 = "alertsvc.exe" nocase wide ascii
        $a13 = "alevir.exe" nocase wide ascii
        $a14 = "alogserv.exe" nocase wide ascii
        $a15 = "amon9x.exe" nocase wide ascii
        $a16 = "anti-trojan.exe" nocase wide ascii
        $a17 = "antivirus.exe" nocase wide ascii
        $a18 = "ants.exe" nocase wide ascii
        $a19 = "apimonitor.exe" nocase wide ascii
        $a20 = "aplica32.exe" nocase wide ascii
        $a21 = "apvxdwin.exe" nocase wide ascii
        $a22 = "arr.exe" nocase wide ascii
        $a23 = "atcon.exe" nocase wide ascii
        $a24 = "atguard.exe" nocase wide ascii
        $a25 = "atro55en.exe" nocase wide ascii
        $a26 = "atupdater.exe" nocase wide ascii
        $a27 = "atwatch.exe" nocase wide ascii
        $a28 = "au.exe" nocase wide ascii
        $a29 = "aupdate.exe" nocase wide ascii
        $a31 = "autodown.exe" nocase wide ascii
        $a32 = "autotrace.exe" nocase wide ascii
        $a33 = "autoupdate.exe" nocase wide ascii
        $a34 = "avconsol.exe" nocase wide ascii
        $a35 = "ave32.exe" nocase wide ascii
        $a36 = "avgcc32.exe" nocase wide ascii
        $a37 = "avgctrl.exe" nocase wide ascii
        $a38 = "avgemc.exe" nocase wide ascii
        $a39 = "avgnt.exe" nocase wide ascii
        $a40 = "avgrsx.exe" nocase wide ascii
        $a41 = "avgserv.exe" nocase wide ascii
        $a42 = "avgserv9.exe" nocase wide ascii
        $a43 = "avguard.exe" nocase wide ascii
        $a44 = "avgw.exe" nocase wide ascii
        $a45 = "avkpop.exe" nocase wide ascii
        $a46 = "avkserv.exe" nocase wide ascii
        $a47 = "avkservice.exe" nocase wide ascii
        $a48 = "avkwctl9.exe" nocase wide ascii
        $a49 = "avltmain.exe" nocase wide ascii
        $a50 = "avnt.exe" nocase wide ascii
        $a51 = "avp.exe" nocase wide ascii
        $a52 = "avp.exe" nocase wide ascii
        $a53 = "avp32.exe" nocase wide ascii
        $a54 = "avpcc.exe" nocase wide ascii
        $a55 = "avpdos32.exe" nocase wide ascii
        $a56 = "avpm.exe" nocase wide ascii
        $a57 = "avptc32.exe" nocase wide ascii
        $a58 = "avpupd.exe" nocase wide ascii
        $a59 = "avsched32.exe" nocase wide ascii
        $a60 = "avsynmgr.exe" nocase wide ascii
        $a61 = "avwin.exe" nocase wide ascii
        $a62 = "avwin95.exe" nocase wide ascii
        $a63 = "avwinnt.exe" nocase wide ascii
        $a64 = "avwupd.exe" nocase wide ascii
        $a65 = "avwupd32.exe" nocase wide ascii
        $a66 = "avwupsrv.exe" nocase wide ascii
        $a67 = "avxmonitor9x.exe" nocase wide ascii
        $a68 = "avxmonitornt.exe" nocase wide ascii
        $a69 = "avxquar.exe" nocase wide ascii
        $a73 = "beagle.exe" nocase wide ascii
        $a74 = "belt.exe" nocase wide ascii
        $a75 = "bidef.exe" nocase wide ascii
        $a76 = "bidserver.exe" nocase wide ascii
        $a77 = "bipcp.exe" nocase wide ascii
        $a79 = "bisp.exe" nocase wide ascii
        $a80 = "blackd.exe" nocase wide ascii
        $a81 = "blackice.exe" nocase wide ascii
        $a82 = "blink.exe" nocase wide ascii
        $a83 = "blss.exe" nocase wide ascii
        $a84 = "bootconf.exe" nocase wide ascii
        $a85 = "bootwarn.exe" nocase wide ascii
        $a86 = "borg2.exe" nocase wide ascii
        $a87 = "bpc.exe" nocase wide ascii
        $a89 = "bs120.exe" nocase wide ascii
        $a90 = "bundle.exe" nocase wide ascii
        $a91 = "bvt.exe" nocase wide ascii
        $a92 = "ccapp.exe" nocase wide ascii
        $a93 = "ccevtmgr.exe" nocase wide ascii
        $a94 = "ccpxysvc.exe" nocase wide ascii
        $a95 = "cdp.exe" nocase wide ascii
        $a96 = "cfd.exe" nocase wide ascii
        $a97 = "cfgwiz.exe" nocase wide ascii
        $a98 = "cfiadmin.exe" nocase wide ascii
        $a99 = "cfiaudit.exe" nocase wide ascii
        $a100 = "cfinet.exe" nocase wide ascii
        $a101 = "cfinet32.exe" nocase wide ascii
        $a102 = "claw95.exe" nocase wide ascii
        $a103 = "claw95cf.exe" nocase wide ascii
        $a104 = "clean.exe" nocase wide ascii
        $a105 = "cleaner.exe" nocase wide ascii
        $a106 = "cleaner3.exe" nocase wide ascii
        $a107 = "cleanpc.exe" nocase wide ascii
        $a108 = "click.exe" nocase wide ascii
        $a111 = "cmesys.exe" nocase wide ascii
        $a112 = "cmgrdian.exe" nocase wide ascii
        $a113 = "cmon016.exe" nocase wide ascii
        $a114 = "connectionmonitor.exe" nocase wide ascii
        $a115 = "cpd.exe" nocase wide ascii
        $a116 = "cpf9x206.exe" nocase wide ascii
        $a117 = "cpfnt206.exe" nocase wide ascii
        $a118 = "ctrl.exe" nocase wide ascii fullword
        $a119 = "cv.exe" nocase wide ascii
        $a120 = "cwnb181.exe" nocase wide ascii
        $a121 = "cwntdwmo.exe" nocase wide ascii
        $a123 = "dcomx.exe" nocase wide ascii
        $a124 = "defalert.exe" nocase wide ascii
        $a125 = "defscangui.exe" nocase wide ascii
        $a126 = "defwatch.exe" nocase wide ascii
        $a127 = "deputy.exe" nocase wide ascii
        $a129 = "dllcache.exe" nocase wide ascii
        $a130 = "dllreg.exe" nocase wide ascii
        $a132 = "dpf.exe" nocase wide ascii
        $a134 = "dpps2.exe" nocase wide ascii
        $a135 = "drwatson.exe" nocase wide ascii
        $a136 = "drweb32.exe" nocase wide ascii
        $a137 = "drwebupw.exe" nocase wide ascii
        $a138 = "dssagent.exe" nocase wide ascii
        $a139 = "dvp95.exe" nocase wide ascii
        $a140 = "dvp95_0.exe" nocase wide ascii
        $a141 = "ecengine.exe" nocase wide ascii
        $a142 = "efpeadm.exe" nocase wide ascii
        $a143 = "emsw.exe" nocase wide ascii
        $a145 = "esafe.exe" nocase wide ascii
        $a146 = "escanhnt.exe" nocase wide ascii
        $a147 = "escanv95.exe" nocase wide ascii
        $a148 = "espwatch.exe" nocase wide ascii
        $a150 = "etrustcipe.exe" nocase wide ascii
        $a151 = "evpn.exe" nocase wide ascii
        $a152 = "exantivirus-cnet.exe" nocase wide ascii
        $a153 = "exe.avxw.exe" nocase wide ascii
        $a154 = "expert.exe" nocase wide ascii
        $a156 = "f-agnt95.exe" nocase wide ascii
        $a157 = "f-prot.exe" nocase wide ascii
        $a158 = "f-prot95.exe" nocase wide ascii
        $a159 = "f-stopw.exe" nocase wide ascii
        $a160 = "fameh32.exe" nocase wide ascii
        $a161 = "fast.exe" nocase wide ascii
        $a162 = "fch32.exe" nocase wide ascii
        $a163 = "fih32.exe" nocase wide ascii
        $a164 = "findviru.exe" nocase wide ascii
        $a165 = "firewall.exe" nocase wide ascii
        $a166 = "fnrb32.exe" nocase wide ascii
        $a167 = "fp-win.exe" nocase wide ascii
        $a169 = "fprot.exe" nocase wide ascii
        $a170 = "frw.exe" nocase wide ascii
        $a171 = "fsaa.exe" nocase wide ascii
        $a172 = "fsav.exe" nocase wide ascii
        $a173 = "fsav32.exe" nocase wide ascii
        $a176 = "fsav95.exe" nocase wide ascii
        $a177 = "fsgk32.exe" nocase wide ascii
        $a178 = "fsm32.exe" nocase wide ascii
        $a179 = "fsma32.exe" nocase wide ascii
        $a180 = "fsmb32.exe" nocase wide ascii
        $a181 = "gator.exe" nocase wide ascii
        $a182 = "gbmenu.exe" nocase wide ascii
        $a183 = "gbpoll.exe" nocase wide ascii
        $a184 = "generics.exe" nocase wide ascii
        $a185 = "gmt.exe" nocase wide ascii
        $a186 = "guard.exe" nocase wide ascii
        $a187 = "guarddog.exe" nocase wide ascii
        $a189 = "hbinst.exe" nocase wide ascii
        $a190 = "hbsrv.exe" nocase wide ascii
        $a191 = "hotactio.exe" nocase wide ascii
        $a192 = "hotpatch.exe" nocase wide ascii
        $a193 = "htlog.exe" nocase wide ascii
        $a194 = "htpatch.exe" nocase wide ascii
        $a195 = "hwpe.exe" nocase wide ascii
        $a196 = "hxdl.exe" nocase wide ascii
        $a197 = "hxiul.exe" nocase wide ascii
        $a198 = "iamapp.exe" nocase wide ascii
        $a199 = "iamserv.exe" nocase wide ascii
        $a200 = "iamstats.exe" nocase wide ascii
        $a201 = "ibmasn.exe" nocase wide ascii
        $a202 = "ibmavsp.exe" nocase wide ascii
        $a203 = "icload95.exe" nocase wide ascii
        $a204 = "icloadnt.exe" nocase wide ascii
        $a205 = "icmon.exe" nocase wide ascii
        $a206 = "icsupp95.exe" nocase wide ascii
        $a207 = "icsuppnt.exe" nocase wide ascii
        $a209 = "iedll.exe" nocase wide ascii
        $a210 = "iedriver.exe" nocase wide ascii
        $a212 = "iface.exe" nocase wide ascii
        $a213 = "ifw2000.exe" nocase wide ascii
        $a214 = "inetlnfo.exe" nocase wide ascii
        $a215 = "infus.exe" nocase wide ascii
        $a216 = "infwin.exe" nocase wide ascii
        $a218 = "intdel.exe" nocase wide ascii
        $a219 = "intren.exe" nocase wide ascii
        $a220 = "iomon98.exe" nocase wide ascii
        $a221 = "istsvc.exe" nocase wide ascii
        $a222 = "jammer.exe" nocase wide ascii
        $a224 = "jedi.exe" nocase wide ascii
        $a227 = "kavpf.exe" nocase wide ascii
        $a228 = "kazza.exe" nocase wide ascii
        $a229 = "keenvalue.exe" nocase wide ascii
        $a236 = "ldnetmon.exe" nocase wide ascii
        $a237 = "ldpro.exe" nocase wide ascii
        $a238 = "ldpromenu.exe" nocase wide ascii
        $a239 = "ldscan.exe" nocase wide ascii
        $a240 = "lnetinfo.exe" nocase wide ascii
        $a242 = "localnet.exe" nocase wide ascii
        $a243 = "lockdown.exe" nocase wide ascii
        $a244 = "lockdown2000.exe" nocase wide ascii
        $a245 = "lookout.exe" nocase wide ascii
        $a248 = "luall.exe" nocase wide ascii
        $a249 = "luau.exe" nocase wide ascii
        $a250 = "lucomserver.exe" nocase wide ascii
        $a251 = "luinit.exe" nocase wide ascii
        $a252 = "luspt.exe" nocase wide ascii
        $a253 = "mapisvc32.exe" nocase wide ascii
        $a254 = "mcagent.exe" nocase wide ascii
        $a255 = "mcmnhdlr.exe" nocase wide ascii
        $a256 = "mcshield.exe" nocase wide ascii
        $a257 = "mctool.exe" nocase wide ascii
        $a258 = "mcupdate.exe" nocase wide ascii
        $a259 = "mcvsrte.exe" nocase wide ascii
        $a260 = "mcvsshld.exe" nocase wide ascii
        $a262 = "mfin32.exe" nocase wide ascii
        $a263 = "mfw2en.exe" nocase wide ascii
        $a265 = "mgavrtcl.exe" nocase wide ascii
        $a266 = "mgavrte.exe" nocase wide ascii
        $a267 = "mghtml.exe" nocase wide ascii
        $a268 = "mgui.exe" nocase wide ascii
        $a269 = "minilog.exe" nocase wide ascii
        $a270 = "mmod.exe" nocase wide ascii
        $a271 = "monitor.exe" nocase wide ascii
        $a272 = "moolive.exe" nocase wide ascii
        $a273 = "mostat.exe" nocase wide ascii
        $a274 = "mpfagent.exe" nocase wide ascii
        $a275 = "mpfservice.exe" nocase wide ascii
        $a276 = "mpftray.exe" nocase wide ascii
        $a277 = "mrflux.exe" nocase wide ascii
        $a278 = "msapp.exe" nocase wide ascii
        $a279 = "msbb.exe" nocase wide ascii
        $a280 = "msblast.exe" nocase wide ascii
        $a281 = "mscache.exe" nocase wide ascii
        $a282 = "msccn32.exe" nocase wide ascii
        $a283 = "mscman.exe" nocase wide ascii
        $a285 = "msdm.exe" nocase wide ascii
        $a286 = "msdos.exe" nocase wide ascii
        $a287 = "msiexec16.exe" nocase wide ascii
        $a288 = "msinfo32.exe" nocase wide ascii
        $a289 = "mslaugh.exe" nocase wide ascii
        $a290 = "msmgt.exe" nocase wide ascii
        $a291 = "msmsgri32.exe" nocase wide ascii
        $a292 = "mssmmc32.exe" nocase wide ascii
        $a293 = "mssys.exe" nocase wide ascii
        $a294 = "msvxd.exe" nocase wide ascii
        $a295 = "mu0311ad.exe" nocase wide ascii
        $a296 = "mwatch.exe" nocase wide ascii
        $a297 = "n32scanw.exe" nocase wide ascii
        $a298 = "nav.exe" nocase wide ascii
        $a300 = "navapsvc.exe" nocase wide ascii
        $a301 = "navapw32.exe" nocase wide ascii
        $a302 = "navdx.exe" nocase wide ascii
        $a303 = "navlu32.exe" nocase wide ascii
        $a304 = "navnt.exe" nocase wide ascii
        $a305 = "navstub.exe" nocase wide ascii
        $a306 = "navw32.exe" nocase wide ascii
        $a307 = "navwnt.exe" nocase wide ascii
        $a308 = "nc2000.exe" nocase wide ascii
        $a309 = "ncinst4.exe" nocase wide ascii
        $a310 = "ndd32.exe" nocase wide ascii
        $a311 = "neomonitor.exe" nocase wide ascii
        $a312 = "neowatchlog.exe" nocase wide ascii
        $a313 = "netarmor.exe" nocase wide ascii
        $a314 = "netd32.exe" nocase wide ascii
        $a315 = "netinfo.exe" nocase wide ascii
        $a317 = "netscanpro.exe" nocase wide ascii
        $a320 = "netutils.exe" nocase wide ascii
        $a321 = "nisserv.exe" nocase wide ascii
        $a322 = "nisum.exe" nocase wide ascii
        $a323 = "nmain.exe" nocase wide ascii
        $a324 = "nod32.exe" nocase wide ascii
        $a325 = "normist.exe" nocase wide ascii
        $a327 = "notstart.exe" nocase wide ascii
        $a329 = "npfmessenger.exe" nocase wide ascii
        $a330 = "nprotect.exe" nocase wide ascii
        $a331 = "npscheck.exe" nocase wide ascii
        $a332 = "npssvc.exe" nocase wide ascii
        $a333 = "nsched32.exe" nocase wide ascii
        $a334 = "nssys32.exe" nocase wide ascii
        $a335 = "nstask32.exe" nocase wide ascii
        $a336 = "nsupdate.exe" nocase wide ascii
        $a338 = "ntrtscan.exe" nocase wide ascii
        $a340 = "ntxconfig.exe" nocase wide ascii
        $a341 = "nui.exe" nocase wide ascii
        $a342 = "nupgrade.exe" nocase wide ascii
        $a343 = "nvarch16.exe" nocase wide ascii
        $a344 = "nvc95.exe" nocase wide ascii
        $a345 = "nvsvc32.exe" nocase wide ascii
        $a346 = "nwinst4.exe" nocase wide ascii
        $a347 = "nwservice.exe" nocase wide ascii
        $a348 = "nwtool16.exe" nocase wide ascii
        $a350 = "onsrvr.exe" nocase wide ascii
        $a351 = "optimize.exe" nocase wide ascii
        $a352 = "ostronet.exe" nocase wide ascii
        $a353 = "otfix.exe" nocase wide ascii
        $a354 = "outpost.exe" nocase wide ascii
        $a360 = "pavcl.exe" nocase wide ascii
        $a361 = "pavproxy.exe" nocase wide ascii
        $a362 = "pavsched.exe" nocase wide ascii
        $a363 = "pavw.exe" nocase wide ascii
        $a364 = "pccwin98.exe" nocase wide ascii
        $a365 = "pcfwallicon.exe" nocase wide ascii
        $a367 = "pcscan.exe" nocase wide ascii
        $a369 = "periscope.exe" nocase wide ascii
        $a370 = "persfw.exe" nocase wide ascii
        $a371 = "perswf.exe" nocase wide ascii
        $a372 = "pf2.exe" nocase wide ascii
        $a373 = "pfwadmin.exe" nocase wide ascii
        $a374 = "pgmonitr.exe" nocase wide ascii
        $a375 = "pingscan.exe" nocase wide ascii
        $a376 = "platin.exe" nocase wide ascii
        $a377 = "pop3trap.exe" nocase wide ascii
        $a378 = "poproxy.exe" nocase wide ascii
        $a379 = "popscan.exe" nocase wide ascii
        $a380 = "portdetective.exe" nocase wide ascii
        $a381 = "portmonitor.exe" nocase wide ascii
        $a382 = "powerscan.exe" nocase wide ascii
        $a383 = "ppinupdt.exe" nocase wide ascii
        $a384 = "pptbc.exe" nocase wide ascii
        $a385 = "ppvstop.exe" nocase wide ascii
        $a387 = "prmt.exe" nocase wide ascii
        $a388 = "prmvr.exe" nocase wide ascii
        $a389 = "procdump.exe" nocase wide ascii
        $a390 = "processmonitor.exe" nocase wide ascii
        $a392 = "programauditor.exe" nocase wide ascii
        $a393 = "proport.exe" nocase wide ascii
        $a394 = "protectx.exe" nocase wide ascii
        $a395 = "pspf.exe" nocase wide ascii
        $a396 = "purge.exe" nocase wide ascii
        $a397 = "qconsole.exe" nocase wide ascii
        $a398 = "qserver.exe" nocase wide ascii
        $a399 = "rapapp.exe" nocase wide ascii
        $a400 = "rav7.exe" nocase wide ascii
        $a401 = "rav7win.exe" nocase wide ascii
        $a404 = "rb32.exe" nocase wide ascii
        $a405 = "rcsync.exe" nocase wide ascii
        $a406 = "realmon.exe" nocase wide ascii
        $a407 = "reged.exe" nocase wide ascii
        $a410 = "rescue.exe" nocase wide ascii
        $a412 = "rrguard.exe" nocase wide ascii
        $a413 = "rshell.exe" nocase wide ascii
        $a414 = "rtvscan.exe" nocase wide ascii
        $a415 = "rtvscn95.exe" nocase wide ascii
        $a416 = "rulaunch.exe" nocase wide ascii
        $a421 = "safeweb.exe" nocase wide ascii
        $a422 = "sahagent.exe" nocase wide ascii
        $a424 = "savenow.exe" nocase wide ascii
        $a425 = "sbserv.exe" nocase wide ascii
        $a428 = "scan32.exe" nocase wide ascii
        $a430 = "scanpm.exe" nocase wide ascii
        $a431 = "scrscan.exe" nocase wide ascii
        $a435 = "sfc.exe" nocase wide ascii
        $a436 = "sgssfw32.exe" nocase wide ascii
        $a439 = "shn.exe" nocase wide ascii
        $a440 = "showbehind.exe" nocase wide ascii
        $a441 = "smc.exe" nocase wide ascii
        $a442 = "sms.exe" nocase wide ascii
        $a443 = "smss32.exe" nocase wide ascii
        $a445 = "sofi.exe" nocase wide ascii
        $a447 = "spf.exe" nocase wide ascii
        $a449 = "spoler.exe" nocase wide ascii
        $a450 = "spoolcv.exe" nocase wide ascii
        $a451 = "spoolsv32.exe" nocase wide ascii
        $a452 = "spyxx.exe" nocase wide ascii
        $a453 = "srexe.exe" nocase wide ascii
        $a454 = "srng.exe" nocase wide ascii
        $a455 = "ss3edit.exe" nocase wide ascii
        $a457 = "ssgrate.exe" nocase wide ascii
        $a458 = "st2.exe" nocase wide ascii fullword
        $a461 = "supftrl.exe" nocase wide ascii
        $a470 = "symproxysvc.exe" nocase wide ascii
        $a471 = "symtray.exe" nocase wide ascii
        $a472 = "sysedit.exe" nocase wide ascii
        $a480 = "taumon.exe" nocase wide ascii
        $a481 = "tbscan.exe" nocase wide ascii
        $a483 = "tca.exe" nocase wide ascii
        $a484 = "tcm.exe" nocase wide ascii
        $a488 = "teekids.exe" nocase wide ascii
        $a489 = "tfak.exe" nocase wide ascii
        $a490 = "tfak5.exe" nocase wide ascii
        $a491 = "tgbob.exe" nocase wide ascii
        $a492 = "titanin.exe" nocase wide ascii
        $a493 = "titaninxp.exe" nocase wide ascii
        $a496 = "trjscan.exe" nocase wide ascii
        $a500 = "tvmd.exe" nocase wide ascii
        $a501 = "tvtmd.exe" nocase wide ascii
        $a513 = "vet32.exe" nocase wide ascii
        $a514 = "vet95.exe" nocase wide ascii
        $a515 = "vettray.exe" nocase wide ascii
        $a517 = "vir-help.exe" nocase wide ascii
        $a519 = "vnlan300.exe" nocase wide ascii
        $a520 = "vnpc3000.exe" nocase wide ascii
        $a521 = "vpc32.exe" nocase wide ascii
        $a522 = "vpc42.exe" nocase wide ascii
        $a523 = "vpfw30s.exe" nocase wide ascii
        $a524 = "vptray.exe" nocase wide ascii
        $a525 = "vscan40.exe" nocase wide ascii
        $a527 = "vsched.exe" nocase wide ascii
        $a528 = "vsecomr.exe" nocase wide ascii
        $a529 = "vshwin32.exe" nocase wide ascii
        $a531 = "vsmain.exe" nocase wide ascii
        $a532 = "vsmon.exe" nocase wide ascii
        $a533 = "vsstat.exe" nocase wide ascii
        $a534 = "vswin9xe.exe" nocase wide ascii
        $a535 = "vswinntse.exe" nocase wide ascii
        $a536 = "vswinperse.exe" nocase wide ascii
        $a537 = "w32dsm89.exe" nocase wide ascii
        $a538 = "w9x.exe" nocase wide ascii
        $a541 = "webscanx.exe" nocase wide ascii
        $a543 = "wfindv32.exe" nocase wide ascii
        $a545 = "wimmun32.exe" nocase wide ascii
        $a566 = "wnad.exe" nocase wide ascii
        $a567 = "wnt.exe" nocase wide ascii
        $a568 = "wradmin.exe" nocase wide ascii
        $a569 = "wrctrl.exe" nocase wide ascii
        $a570 = "wsbgate.exe" nocase wide ascii
        $a573 = "wyvernworksfirewall.exe" nocase wide ascii
        $a575 = "zapro.exe" nocase wide ascii
        $a577 = "zatutor.exe" nocase wide ascii
        $a579 = "zonealarm.exe" nocase wide ascii

    condition:
        any of them
}

rule VM_Generic_Detection : AntiVM
{
    meta:
        description = "Tries to detect virtualized environments"
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
        description = "Looks for VMWare presence"
        author = "Cuckoo project"

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

		// PCI Vendor IDs, from Hacking Team's leak
		$virtualbox_vid_1 = "VEN_15ad" nocase wide ascii

    condition:
        any of them
}

rule Sandboxie_Detection : AntiVM
{
    meta:
        description = "Looks for Sandboxie presence"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $sbie = "SbieDll.dll" nocase wide ascii
        $buster = /LOG_API(_VERBOSE)?.DLL/ nocase wide ascii

    condition:
        any of them
}

rule VirtualPC_Detection : AntiVM
{
    meta:
        description = "Looks for VirtualPC presence"
        author = "Cuckoo project"

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
        description = "Looks for VirtualBox presence"
        author = "Cuckoo project"
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

		// PCI Vendor IDs, from Hacking Team's leak
		$virtualbox_vid_1 = "VEN_80EE" nocase wide ascii
    condition:
        any of them
}

rule Parallels_Detection : AntiVM
{
    meta:
        description = "Looks for Parallels presence"
    strings:
        $a0 = "magi"
        $a1 = "c!nu"
        $a2 = "mber"

		// PCI Vendor IDs, from Hacking Team's leak
		$parallels_vid_1 = "VEN_80EE" nocase wide ascii
    condition:
        all of them
}

rule Qemu_Detection : AntiVM
{
    meta:
        description = "Looks for Qemu presence"
    strings:
        $a0 = "qemu" nocase wide ascii
    condition:
        any of them
}

rule Dropper_Strings
{
    meta:
        description = "May have dropper capabilities"
        author = "Ivan Kwiatkowski (@JusticeRage)"
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
        description = "Is an AutoIT compiled script"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = "AutoIt Error" ascii wide
        $a1 = "reserved for AutoIt internal use" ascii wide
    condition:
        any of them
}

rule WMI_strings
{
	meta:
		description = "Accesses the WMI"
		author = "Ivan Kwiatkowski (@JusticeRage)"
	strings:
		// WMI namespaces which may be referenced in the ConnectServer call. All in the form of "ROOT\something"
		$a0 = /ROOT\\(CIMV2|AccessLogging|ADFS|aspnet|Cli|Hardware|interop|InventoryLogging|Microsoft.{10}|Policy|RSOP|SECURITY|ServiceModel|snmpStandardCimv2|subscription|virtualization|WebAdministration|WMI)/ nocase ascii wide
	condition:
		any of them
}

rule Misc_Suspicious_Strings
{
    meta:
        description = "Miscellaneous malware strings"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a0 = "backdoor" nocase ascii wide
        $a1 = "virus" nocase ascii wide
        $a2 = "hack" nocase ascii wide
        $a3 = "exploit" nocase ascii wide
        $a4 = "cmd.exe" nocase ascii wide
        $a5 = "CWSandbox" nocase wide ascii // Found in some Zeus/Citadel samples
    condition:
        any of them
}
