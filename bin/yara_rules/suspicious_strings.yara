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
        $a12 = "vssadmin.exe" nocase wide ascii
        $a13 = "bcdedit.exe" nocase wide ascii
        $a14 = "dumpcap.exe" nocase wide ascii
        $a15 = "tcpdump.exe" nocase wide ascii
		$a16 = "mshta.exe" nocase wide ascii    // Used by DUBNIUM to download files
        $a17 = "control.exe" nocase wide ascii  // Used by EquationGroup to launch DLLs
        $a18 = "regsvr32.exe" nocase wide ascii
        $a19 = "rundll32.exe" nocase wide ascii
        $a20 = /schtask(.exe)?/ nocase wide ascii
		$a21 = "wbadmin.exe" nocase wide ascii
		$a22 = "wevutil.exe" nocase wide ascii
		
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
        // x64dbg (credit goes to @_pusher_0x90)
        $a6 = "x32dbg.exe" nocase wide ascii
        $a7 = "x64dbg.exe" nocase wide ascii

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
        $a43 = /av(gui|guard|center|gtray|gidsagent|gwdsvc|grsa|gcsrva|gcsrvx).exe/ nocase wide ascii
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
		// Strings from Dubnium below
		$a580 = "QQPCRTP.exe" nocase wide ascii
		$a581 = "QQPCTray.exe" nocase wide ascii
		$a582 = "ZhuDongFangYu.exe" nocase wide ascii
		$a583 = /360(tray|sd|rp).exe/ nocase wide ascii
		$a584 = /qh(safetray|watchdog|activedefense).exe/ nocase wide ascii
		$a585 = "McNASvc.exe" nocase wide ascii
		$a586 = "MpfSrv.exe" nocase wide ascii
		$a587 = "McProxy.exe" nocase wide ascii
		$a588 = "mcmscsvc.exe" nocase wide ascii
		$a589 = "McUICnt.exe" nocase wide ascii
		$a590 = /ui(WatchDog|seagnt|winmgr).exe/ nocase wide ascii
		$a591 = "ufseagnt.exe" nocase wide ascii
		$a592 = /core(serviceshell|frameworkhost).exe/ nocase wide ascii
		$a593 = /ay(agent|rtsrv|updsrv).aye/ nocase wide ascii
		$a594 = /avast(ui|svc).exe/ nocase wide ascii
		$a595 = /ms(seces|mpeng).exe/ nocase wide ascii
		$a596 = "afwserv.exe" nocase wide ascii
		$a597 = "FiddlerUser"
		
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
        $a2 = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation" nocase wide ascii
        $a3 = "SYSTEM\\CurrentControlSet\\Enum\\IDE" nocase wide ascii
        $redpill = { 0F 01 0D 00 00 00 00 C3 } // Copied from the Cuckoo project
        
        // CLSIDs used to detect if speakers are present. Hoping this will not cause false positives.
        $teslacrypt1 = { D1 29 06 E3 E5 27 CE 11 87 5D 00 60 8C B7 80 66 } // CLSID_AudioRender
        $teslacrypt2 = { B3 EB 36 E4 4F 52 CE 11 9F 53 00 20 AF 0B A7 70 } // CLSID_FilterGraph
        
    condition:
        any of ($a*) or $redpill or all of ($teslacrypt*)
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
        $sbie_process_1 = "SbieSvc.exe" nocase wide ascii
        $sbie_process_2 = "SbieCtrl.exe" nocase wide ascii
        $sbie_process_3 = "SandboxieRpcSs.exe" nocase wide ascii
        $sbie_process_4 = "SandboxieDcomLaunch.exe" nocase wide ascii
        $sbie_process_5 = "SandboxieCrypto.exe" nocase wide ascii
        $sbie_process_6 = "SandboxieBITS.exe" nocase wide ascii
        $sbie_process_7 = "SandboxieWUAU.exe" nocase wide ascii

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
        
        // Registry keys
        $virtualbox_reg_1 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase wide ascii
        $virtualbox_reg_2 = /HARDWARE\\ACPI\\(DSDT|FADT|RSDT)\\VBOX__/ nocase wide ascii
        
        // Other
        $virtualbox_files = /C:\\Windows\\System32\\drivers\\vbox.{15}\.(sys|dll)/ nocase wide ascii
        $virtualbox_services = "System\\ControlSet001\\Services\\VBox[A-Za-z]+" nocase wide ascii
        $virtualbox_pipe = /\\\\.\\pipe\\(VBoxTrayIPC|VBoxMiniRdDN)/ nocase wide ascii
        $virtualbox_window = /VBoxTrayToolWnd(Class)?/ nocase wide ascii
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
        $a0 = /ROOT\\(CIMV2|AccessLogging|ADFS|aspnet|Cli|Hardware|interop|InventoryLogging|Microsoft|Policy|RSOP|SECURITY|ServiceModel|snmp|StandardCimv2|subscription|virtualization|WebAdministration|WMI)/ nocase ascii wide
    condition:
        any of them
}

rule Obfuscated_Strings
{
	meta:
		description = "Contains obfuscated function names"
		author = "Ivan Kwiatkowski (@JusticeRage)"
	strings:
		$a0 = { (46 | 66) 64 75 (51 | 71) 73 6E 62 (40 | 60) 65 65 73 64 72 72 } // [Gg]et[Pp]roc[Aa]ddress XOR 0x01
		$a1 = { (45 | 65) 67 76 (52 | 72) 70 6D 61 (43 | 63) 66 66 70 67 71 71 } // GetProcAddress XOR 0x02
		$a2 = { (44 | 64) 66 77 (53 | 73) 71 6C 60 (42 | 62) 67 67 71 66 70 70 } // etc...
		$a3 = { (43 | 63) 61 70 (54 | 74) 76 6B 67 (45 | 65) 60 60 76 61 77 77 }
		$a4 = { (42 | 62) 60 71 (55 | 75) 77 6A 66 (44 | 64) 61 61 77 60 76 76 }
		$a5 = { (41 | 61) 63 72 (56 | 76) 74 69 65 (47 | 67) 62 62 74 63 75 75 }
		$a6 = { (40 | 60) 62 73 (57 | 77) 75 68 64 (46 | 66) 63 63 75 62 74 74 }
		$a7 = { (4F | 6F) 6D 7C (58 | 78) 7A 67 6B (49 | 69) 6C 6C 7A 6D 7B 7B }
		$a8 = { (4E | 6E) 6C 7D (59 | 79) 7B 66 6A (48 | 68) 6D 6D 7B 6C 7A 7A }
		$a9 = { (4D | 6D) 6F 7E (5A | 7A) 78 65 69 (4B | 6B) 6E 6E 78 6F 79 79 }
		$a10 = { (4C | 6C) 6E 7F (5B | 7B) 79 64 68 (4A | 6A) 6F 6F 79 6E 78 78 }
		$a11 = { (4B | 6B) 69 78 (5C | 7C) 7E 63 6F (4D | 6D) 68 68 7E 69 7F 7F }
		$a12 = { (4A | 6A) 68 79 (5D | 7D) 7F 62 6E (4C | 6C) 69 69 7F 68 7E 7E }
		$a13 = { (49 | 69) 6B 7A (5E | 7E) 7C 61 6D (4F | 6F) 6A 6A 7C 6B 7D 7D }
		$a14 = { (48 | 68) 6A 7B (5F | 7F) 7D 60 6C (4E | 6E) 6B 6B 7D 6A 7C 7C }
		$a15 = { (57 | 77) 75 64 (40 | 60) 62 7F 73 (51 | 71) 74 74 62 75 63 63 }
		$a16 = { (56 | 76) 74 65 (41 | 61) 63 7E 72 (50 | 70) 75 75 63 74 62 62 }
		$a17 = { (55 | 75) 77 66 (42 | 62) 60 7D 71 (53 | 73) 76 76 60 77 61 61 }
		$a18 = { (54 | 74) 76 67 (43 | 63) 61 7C 70 (52 | 72) 77 77 61 76 60 60 }
		$a19 = { (53 | 73) 71 60 (44 | 64) 66 7B 77 (55 | 75) 70 70 66 71 67 67 }
		$a20 = { (52 | 72) 70 61 (45 | 65) 67 7A 76 (54 | 74) 71 71 67 70 66 66 }
		$a21 = { (51 | 71) 73 62 (46 | 66) 64 79 75 (57 | 77) 72 72 64 73 65 65 }
		$a22 = { (50 | 70) 72 63 (47 | 67) 65 78 74 (56 | 76) 73 73 65 72 64 64 }
		$a23 = { (5F | 7F) 7D 6C (48 | 68) 6A 77 7B (59 | 79) 7C 7C 6A 7D 6B 6B }
		$a24 = { (5E | 7E) 7C 6D (49 | 69) 6B 76 7A (58 | 78) 7D 7D 6B 7C 6A 6A }
		$a25 = { (5D | 7D) 7F 6E (4A | 6A) 68 75 79 (5B | 7B) 7E 7E 68 7F 69 69 }
		$a26 = { (5C | 7C) 7E 6F (4B | 6B) 69 74 78 (5A | 7A) 7F 7F 69 7E 68 68 }
		$a27 = { (5B | 7B) 79 68 (4C | 6C) 6E 73 7F (5D | 7D) 78 78 6E 79 6F 6F }
		$a28 = { (5A | 7A) 78 69 (4D | 6D) 6F 72 7E (5C | 7C) 79 79 6F 78 6E 6E }
		$a29 = { (59 | 79) 7B 6A (4E | 6E) 6C 71 7D (5F | 7F) 7A 7A 6C 7B 6D 6D }
		$a30 = { (58 | 78) 7A 6B (4F | 6F) 6D 70 7C (5E | 7E) 7B 7B 6D 7A 6C 6C }
		// XOR 0x20 removed because it toggles capitalization and causes [Gg]ET[Pp]ROC[Aa]DDRESS to match.
		$a32 = { (66 | 46) 44 55 (71 | 51) 53 4E 42 (60 | 40) 45 45 53 44 52 52 }
		$a33 = { (65 | 45) 47 56 (72 | 52) 50 4D 41 (63 | 43) 46 46 50 47 51 51 }
		$a34 = { (64 | 44) 46 57 (73 | 53) 51 4C 40 (62 | 42) 47 47 51 46 50 50 }
		$a35 = { (63 | 43) 41 50 (74 | 54) 56 4B 47 (65 | 45) 40 40 56 41 57 57 }
		$a36 = { (62 | 42) 40 51 (75 | 55) 57 4A 46 (64 | 44) 41 41 57 40 56 56 }
		$a37 = { (61 | 41) 43 52 (76 | 56) 54 49 45 (67 | 47) 42 42 54 43 55 55 }
		$a38 = { (60 | 40) 42 53 (77 | 57) 55 48 44 (66 | 46) 43 43 55 42 54 54 }
		$a39 = { (6F | 4F) 4D 5C (78 | 58) 5A 47 4B (69 | 49) 4C 4C 5A 4D 5B 5B }
		$a40 = { (6E | 4E) 4C 5D (79 | 59) 5B 46 4A (68 | 48) 4D 4D 5B 4C 5A 5A }
		$a41 = { (6D | 4D) 4F 5E (7A | 5A) 58 45 49 (6B | 4B) 4E 4E 58 4F 59 59 }
		$a42 = { (6C | 4C) 4E 5F (7B | 5B) 59 44 48 (6A | 4A) 4F 4F 59 4E 58 58 }
		$a43 = { (6B | 4B) 49 58 (7C | 5C) 5E 43 4F (6D | 4D) 48 48 5E 49 5F 5F }
		$a44 = { (6A | 4A) 48 59 (7D | 5D) 5F 42 4E (6C | 4C) 49 49 5F 48 5E 5E }
		$a45 = { (69 | 49) 4B 5A (7E | 5E) 5C 41 4D (6F | 4F) 4A 4A 5C 4B 5D 5D }
		$a46 = { (68 | 48) 4A 5B (7F | 5F) 5D 40 4C (6E | 4E) 4B 4B 5D 4A 5C 5C }
		$a47 = { (77 | 57) 55 44 (60 | 40) 42 5F 53 (71 | 51) 54 54 42 55 43 43 }
		$a48 = { (76 | 56) 54 45 (61 | 41) 43 5E 52 (70 | 50) 55 55 43 54 42 42 }
		$a49 = { (75 | 55) 57 46 (62 | 42) 40 5D 51 (73 | 53) 56 56 40 57 41 41 }
		$a50 = { (74 | 54) 56 47 (63 | 43) 41 5C 50 (72 | 52) 57 57 41 56 40 40 }
		$a51 = { (73 | 53) 51 40 (64 | 44) 46 5B 57 (75 | 55) 50 50 46 51 47 47 }
		$a52 = { (72 | 52) 50 41 (65 | 45) 47 5A 56 (74 | 54) 51 51 47 50 46 46 }
		$a53 = { (71 | 51) 53 42 (66 | 46) 44 59 55 (77 | 57) 52 52 44 53 45 45 }
		$a54 = { (70 | 50) 52 43 (67 | 47) 45 58 54 (76 | 56) 53 53 45 52 44 44 }
		$a55 = { (7F | 5F) 5D 4C (68 | 48) 4A 57 5B (79 | 59) 5C 5C 4A 5D 4B 4B }
		$a56 = { (7E | 5E) 5C 4D (69 | 49) 4B 56 5A (78 | 58) 5D 5D 4B 5C 4A 4A }
		$a57 = { (7D | 5D) 5F 4E (6A | 4A) 48 55 59 (7B | 5B) 5E 5E 48 5F 49 49 }
		$a58 = { (7C | 5C) 5E 4F (6B | 4B) 49 54 58 (7A | 5A) 5F 5F 49 5E 48 48 }
		$a59 = { (7B | 5B) 59 48 (6C | 4C) 4E 53 5F (7D | 5D) 58 58 4E 59 4F 4F }
		$a60 = { (7A | 5A) 58 49 (6D | 4D) 4F 52 5E (7C | 5C) 59 59 4F 58 4E 4E }
		$a61 = { (79 | 59) 5B 4A (6E | 4E) 4C 51 5D (7F | 5F) 5A 5A 4C 5B 4D 4D }
		$a62 = { (78 | 58) 5A 4B (6F | 4F) 4D 50 5C (7E | 5E) 5B 5B 4D 5A 4C 4C }
		$a63 = { (07 | 27) 25 34 (10 | 30) 32 2F 23 (01 | 21) 24 24 32 25 33 33 }
		$a64 = { (06 | 26) 24 35 (11 | 31) 33 2E 22 (00 | 20) 25 25 33 24 32 32 }
		$a65 = { (05 | 25) 27 36 (12 | 32) 30 2D 21 (03 | 23) 26 26 30 27 31 31 }
		$a66 = { (04 | 24) 26 37 (13 | 33) 31 2C 20 (02 | 22) 27 27 31 26 30 30 }
		$a67 = { (03 | 23) 21 30 (14 | 34) 36 2B 27 (05 | 25) 20 20 36 21 37 37 }
		$a68 = { (02 | 22) 20 31 (15 | 35) 37 2A 26 (04 | 24) 21 21 37 20 36 36 }
		$a69 = { (01 | 21) 23 32 (16 | 36) 34 29 25 (07 | 27) 22 22 34 23 35 35 }
		$a70 = { (00 | 20) 22 33 (17 | 37) 35 28 24 (06 | 26) 23 23 35 22 34 34 }
		$a71 = { (0F | 2F) 2D 3C (18 | 38) 3A 27 2B (09 | 29) 2C 2C 3A 2D 3B 3B }
		$a72 = { (0E | 2E) 2C 3D (19 | 39) 3B 26 2A (08 | 28) 2D 2D 3B 2C 3A 3A }
		$a73 = { (0D | 2D) 2F 3E (1A | 3A) 38 25 29 (0B | 2B) 2E 2E 38 2F 39 39 }
		$a74 = { (0C | 2C) 2E 3F (1B | 3B) 39 24 28 (0A | 2A) 2F 2F 39 2E 38 38 }
		$a75 = { (0B | 2B) 29 38 (1C | 3C) 3E 23 2F (0D | 2D) 28 28 3E 29 3F 3F }
		$a76 = { (0A | 2A) 28 39 (1D | 3D) 3F 22 2E (0C | 2C) 29 29 3F 28 3E 3E }
		$a77 = { (09 | 29) 2B 3A (1E | 3E) 3C 21 2D (0F | 2F) 2A 2A 3C 2B 3D 3D }
		$a78 = { (08 | 28) 2A 3B (1F | 3F) 3D 20 2C (0E | 2E) 2B 2B 3D 2A 3C 3C }
		$a79 = { (17 | 37) 35 24 (00 | 20) 22 3F 33 (11 | 31) 34 34 22 35 23 23 }
		$a80 = { (16 | 36) 34 25 (01 | 21) 23 3E 32 (10 | 30) 35 35 23 34 22 22 }
		$a81 = { (15 | 35) 37 26 (02 | 22) 20 3D 31 (13 | 33) 36 36 20 37 21 21 }
		$a82 = { (14 | 34) 36 27 (03 | 23) 21 3C 30 (12 | 32) 37 37 21 36 20 20 }
		$a83 = { (13 | 33) 31 20 (04 | 24) 26 3B 37 (15 | 35) 30 30 26 31 27 27 }
		$a84 = { (12 | 32) 30 21 (05 | 25) 27 3A 36 (14 | 34) 31 31 27 30 26 26 }
		$a85 = { (11 | 31) 33 22 (06 | 26) 24 39 35 (17 | 37) 32 32 24 33 25 25 }
		$a86 = { (10 | 30) 32 23 (07 | 27) 25 38 34 (16 | 36) 33 33 25 32 24 24 }
		$a87 = { (1F | 3F) 3D 2C (08 | 28) 2A 37 3B (19 | 39) 3C 3C 2A 3D 2B 2B }
		$a88 = { (1E | 3E) 3C 2D (09 | 29) 2B 36 3A (18 | 38) 3D 3D 2B 3C 2A 2A }
		$a89 = { (1D | 3D) 3F 2E (0A | 2A) 28 35 39 (1B | 3B) 3E 3E 28 3F 29 29 }
		$a90 = { (1C | 3C) 3E 2F (0B | 2B) 29 34 38 (1A | 3A) 3F 3F 29 3E 28 28 }
		$a91 = { (1B | 3B) 39 28 (0C | 2C) 2E 33 3F (1D | 3D) 38 38 2E 39 2F 2F }
		$a92 = { (1A | 3A) 38 29 (0D | 2D) 2F 32 3E (1C | 3C) 39 39 2F 38 2E 2E }
		$a93 = { (19 | 39) 3B 2A (0E | 2E) 2C 31 3D (1F | 3F) 3A 3A 2C 3B 2D 2D }
		$a94 = { (18 | 38) 3A 2B (0F | 2F) 2D 30 3C (1E | 3E) 3B 3B 2D 3A 2C 2C }
		$a95 = { (27 | 07) 05 14 (30 | 10) 12 0F 03 (21 | 01) 04 04 12 05 13 13 }
		$a96 = { (26 | 06) 04 15 (31 | 11) 13 0E 02 (20 | 00) 05 05 13 04 12 12 }
		$a97 = { (25 | 05) 07 16 (32 | 12) 10 0D 01 (23 | 03) 06 06 10 07 11 11 }
		$a98 = { (24 | 04) 06 17 (33 | 13) 11 0C 00 (22 | 02) 07 07 11 06 10 10 }
		$a99 = { (23 | 03) 01 10 (34 | 14) 16 0B 07 (25 | 05) 00 00 16 01 17 17 }
		$a100 = { (22 | 02) 00 11 (35 | 15) 17 0A 06 (24 | 04) 01 01 17 00 16 16 }
		$a101 = { (21 | 01) 03 12 (36 | 16) 14 09 05 (27 | 07) 02 02 14 03 15 15 }
		$a102 = { (20 | 00) 02 13 (37 | 17) 15 08 04 (26 | 06) 03 03 15 02 14 14 }
		$a103 = { (2F | 0F) 0D 1C (38 | 18) 1A 07 0B (29 | 09) 0C 0C 1A 0D 1B 1B }
		$a104 = { (2E | 0E) 0C 1D (39 | 19) 1B 06 0A (28 | 08) 0D 0D 1B 0C 1A 1A }
		$a105 = { (2D | 0D) 0F 1E (3A | 1A) 18 05 09 (2B | 0B) 0E 0E 18 0F 19 19 }
		$a106 = { (2C | 0C) 0E 1F (3B | 1B) 19 04 08 (2A | 0A) 0F 0F 19 0E 18 18 }
		$a107 = { (2B | 0B) 09 18 (3C | 1C) 1E 03 0F (2D | 0D) 08 08 1E 09 1F 1F }
		$a108 = { (2A | 0A) 08 19 (3D | 1D) 1F 02 0E (2C | 0C) 09 09 1F 08 1E 1E }
		$a109 = { (29 | 09) 0B 1A (3E | 1E) 1C 01 0D (2F | 0F) 0A 0A 1C 0B 1D 1D }
		$a110 = { (28 | 08) 0A 1B (3F | 1F) 1D 00 0C (2E | 0E) 0B 0B 1D 0A 1C 1C }
		$a111 = { (37 | 17) 15 04 (20 | 00) 02 1F 13 (31 | 11) 14 14 02 15 03 03 }
		$a112 = { (36 | 16) 14 05 (21 | 01) 03 1E 12 (30 | 10) 15 15 03 14 02 02 }
		$a113 = { (35 | 15) 17 06 (22 | 02) 00 1D 11 (33 | 13) 16 16 00 17 01 01 }
		$a114 = { (34 | 14) 16 07 (23 | 03) 01 1C 10 (32 | 12) 17 17 01 16 00 00 }
		$a115 = { (33 | 13) 11 00 (24 | 04) 06 1B 17 (35 | 15) 10 10 06 11 07 07 }
		$a116 = { (32 | 12) 10 01 (25 | 05) 07 1A 16 (34 | 14) 11 11 07 10 06 06 }
		$a117 = { (31 | 11) 13 02 (26 | 06) 04 19 15 (37 | 17) 12 12 04 13 05 05 }
		$a118 = { (30 | 10) 12 03 (27 | 07) 05 18 14 (36 | 16) 13 13 05 12 04 04 }
		$a119 = { (3F | 1F) 1D 0C (28 | 08) 0A 17 1B (39 | 19) 1C 1C 0A 1D 0B 0B }
		$a120 = { (3E | 1E) 1C 0D (29 | 09) 0B 16 1A (38 | 18) 1D 1D 0B 1C 0A 0A }
		$a121 = { (3D | 1D) 1F 0E (2A | 0A) 08 15 19 (3B | 1B) 1E 1E 08 1F 09 09 }
		$a122 = { (3C | 1C) 1E 0F (2B | 0B) 09 14 18 (3A | 1A) 1F 1F 09 1E 08 08 }
		$a123 = { (3B | 1B) 19 08 (2C | 0C) 0E 13 1F (3D | 1D) 18 18 0E 19 0F 0F }
		$a124 = { (3A | 1A) 18 09 (2D | 0D) 0F 12 1E (3C | 1C) 19 19 0F 18 0E 0E }
		$a125 = { (39 | 19) 1B 0A (2E | 0E) 0C 11 1D (3F | 1F) 1A 1A 0C 1B 0D 0D }
		$a126 = { (38 | 18) 1A 0B (2F | 0F) 0D 10 1C (3E | 1E) 1B 1B 0D 1A 0C 0C }
		$a127 = { (C7 | E7) E5 F4 (D0 | F0) F2 EF E3 (C1 | E1) E4 E4 F2 E5 F3 F3 }
		$a128 = { (C6 | E6) E4 F5 (D1 | F1) F3 EE E2 (C0 | E0) E5 E5 F3 E4 F2 F2 }
		$a129 = { (C5 | E5) E7 F6 (D2 | F2) F0 ED E1 (C3 | E3) E6 E6 F0 E7 F1 F1 }
		$a130 = { (C4 | E4) E6 F7 (D3 | F3) F1 EC E0 (C2 | E2) E7 E7 F1 E6 F0 F0 }
		$a131 = { (C3 | E3) E1 F0 (D4 | F4) F6 EB E7 (C5 | E5) E0 E0 F6 E1 F7 F7 }
		$a132 = { (C2 | E2) E0 F1 (D5 | F5) F7 EA E6 (C4 | E4) E1 E1 F7 E0 F6 F6 }
		$a133 = { (C1 | E1) E3 F2 (D6 | F6) F4 E9 E5 (C7 | E7) E2 E2 F4 E3 F5 F5 }
		$a134 = { (C0 | E0) E2 F3 (D7 | F7) F5 E8 E4 (C6 | E6) E3 E3 F5 E2 F4 F4 }
		$a135 = { (CF | EF) ED FC (D8 | F8) FA E7 EB (C9 | E9) EC EC FA ED FB FB }
		$a136 = { (CE | EE) EC FD (D9 | F9) FB E6 EA (C8 | E8) ED ED FB EC FA FA }
		$a137 = { (CD | ED) EF FE (DA | FA) F8 E5 E9 (CB | EB) EE EE F8 EF F9 F9 }
		$a138 = { (CC | EC) EE FF (DB | FB) F9 E4 E8 (CA | EA) EF EF F9 EE F8 F8 }
		$a139 = { (CB | EB) E9 F8 (DC | FC) FE E3 EF (CD | ED) E8 E8 FE E9 FF FF }
		$a140 = { (CA | EA) E8 F9 (DD | FD) FF E2 EE (CC | EC) E9 E9 FF E8 FE FE }
		$a141 = { (C9 | E9) EB FA (DE | FE) FC E1 ED (CF | EF) EA EA FC EB FD FD }
		$a142 = { (C8 | E8) EA FB (DF | FF) FD E0 EC (CE | EE) EB EB FD EA FC FC }
		$a143 = { (D7 | F7) F5 E4 (C0 | E0) E2 FF F3 (D1 | F1) F4 F4 E2 F5 E3 E3 }
		$a144 = { (D6 | F6) F4 E5 (C1 | E1) E3 FE F2 (D0 | F0) F5 F5 E3 F4 E2 E2 }
		$a145 = { (D5 | F5) F7 E6 (C2 | E2) E0 FD F1 (D3 | F3) F6 F6 E0 F7 E1 E1 }
		$a146 = { (D4 | F4) F6 E7 (C3 | E3) E1 FC F0 (D2 | F2) F7 F7 E1 F6 E0 E0 }
		$a147 = { (D3 | F3) F1 E0 (C4 | E4) E6 FB F7 (D5 | F5) F0 F0 E6 F1 E7 E7 }
		$a148 = { (D2 | F2) F0 E1 (C5 | E5) E7 FA F6 (D4 | F4) F1 F1 E7 F0 E6 E6 }
		$a149 = { (D1 | F1) F3 E2 (C6 | E6) E4 F9 F5 (D7 | F7) F2 F2 E4 F3 E5 E5 }
		$a150 = { (D0 | F0) F2 E3 (C7 | E7) E5 F8 F4 (D6 | F6) F3 F3 E5 F2 E4 E4 }
		$a151 = { (DF | FF) FD EC (C8 | E8) EA F7 FB (D9 | F9) FC FC EA FD EB EB }
		$a152 = { (DE | FE) FC ED (C9 | E9) EB F6 FA (D8 | F8) FD FD EB FC EA EA }
		$a153 = { (DD | FD) FF EE (CA | EA) E8 F5 F9 (DB | FB) FE FE E8 FF E9 E9 }
		$a154 = { (DC | FC) FE EF (CB | EB) E9 F4 F8 (DA | FA) FF FF E9 FE E8 E8 }
		$a155 = { (DB | FB) F9 E8 (CC | EC) EE F3 FF (DD | FD) F8 F8 EE F9 EF EF }
		$a156 = { (DA | FA) F8 E9 (CD | ED) EF F2 FE (DC | FC) F9 F9 EF F8 EE EE }
		$a157 = { (D9 | F9) FB EA (CE | EE) EC F1 FD (DF | FF) FA FA EC FB ED ED }
		$a158 = { (D8 | F8) FA EB (CF | EF) ED F0 FC (DE | FE) FB FB ED FA EC EC }
		$a159 = { (E7 | C7) C5 D4 (F0 | D0) D2 CF C3 (E1 | C1) C4 C4 D2 C5 D3 D3 }
		$a160 = { (E6 | C6) C4 D5 (F1 | D1) D3 CE C2 (E0 | C0) C5 C5 D3 C4 D2 D2 }
		$a161 = { (E5 | C5) C7 D6 (F2 | D2) D0 CD C1 (E3 | C3) C6 C6 D0 C7 D1 D1 }
		$a162 = { (E4 | C4) C6 D7 (F3 | D3) D1 CC C0 (E2 | C2) C7 C7 D1 C6 D0 D0 }
		$a163 = { (E3 | C3) C1 D0 (F4 | D4) D6 CB C7 (E5 | C5) C0 C0 D6 C1 D7 D7 }
		$a164 = { (E2 | C2) C0 D1 (F5 | D5) D7 CA C6 (E4 | C4) C1 C1 D7 C0 D6 D6 }
		$a165 = { (E1 | C1) C3 D2 (F6 | D6) D4 C9 C5 (E7 | C7) C2 C2 D4 C3 D5 D5 }
		$a166 = { (E0 | C0) C2 D3 (F7 | D7) D5 C8 C4 (E6 | C6) C3 C3 D5 C2 D4 D4 }
		$a167 = { (EF | CF) CD DC (F8 | D8) DA C7 CB (E9 | C9) CC CC DA CD DB DB }
		$a168 = { (EE | CE) CC DD (F9 | D9) DB C6 CA (E8 | C8) CD CD DB CC DA DA }
		$a169 = { (ED | CD) CF DE (FA | DA) D8 C5 C9 (EB | CB) CE CE D8 CF D9 D9 }
		$a170 = { (EC | CC) CE DF (FB | DB) D9 C4 C8 (EA | CA) CF CF D9 CE D8 D8 }
		$a171 = { (EB | CB) C9 D8 (FC | DC) DE C3 CF (ED | CD) C8 C8 DE C9 DF DF }
		$a172 = { (EA | CA) C8 D9 (FD | DD) DF C2 CE (EC | CC) C9 C9 DF C8 DE DE }
		$a173 = { (E9 | C9) CB DA (FE | DE) DC C1 CD (EF | CF) CA CA DC CB DD DD }
		$a174 = { (E8 | C8) CA DB (FF | DF) DD C0 CC (EE | CE) CB CB DD CA DC DC }
		$a175 = { (F7 | D7) D5 C4 (E0 | C0) C2 DF D3 (F1 | D1) D4 D4 C2 D5 C3 C3 }
		$a176 = { (F6 | D6) D4 C5 (E1 | C1) C3 DE D2 (F0 | D0) D5 D5 C3 D4 C2 C2 }
		$a177 = { (F5 | D5) D7 C6 (E2 | C2) C0 DD D1 (F3 | D3) D6 D6 C0 D7 C1 C1 }
		$a178 = { (F4 | D4) D6 C7 (E3 | C3) C1 DC D0 (F2 | D2) D7 D7 C1 D6 C0 C0 }
		$a179 = { (F3 | D3) D1 C0 (E4 | C4) C6 DB D7 (F5 | D5) D0 D0 C6 D1 C7 C7 }
		$a180 = { (F2 | D2) D0 C1 (E5 | C5) C7 DA D6 (F4 | D4) D1 D1 C7 D0 C6 C6 }
		$a181 = { (F1 | D1) D3 C2 (E6 | C6) C4 D9 D5 (F7 | D7) D2 D2 C4 D3 C5 C5 }
		$a182 = { (F0 | D0) D2 C3 (E7 | C7) C5 D8 D4 (F6 | D6) D3 D3 C5 D2 C4 C4 }
		$a183 = { (FF | DF) DD CC (E8 | C8) CA D7 DB (F9 | D9) DC DC CA DD CB CB }
		$a184 = { (FE | DE) DC CD (E9 | C9) CB D6 DA (F8 | D8) DD DD CB DC CA CA }
		$a185 = { (FD | DD) DF CE (EA | CA) C8 D5 D9 (FB | DB) DE DE C8 DF C9 C9 }
		$a186 = { (FC | DC) DE CF (EB | CB) C9 D4 D8 (FA | DA) DF DF C9 DE C8 C8 }
		$a187 = { (FB | DB) D9 C8 (EC | CC) CE D3 DF (FD | DD) D8 D8 CE D9 CF CF }
		$a188 = { (FA | DA) D8 C9 (ED | CD) CF D2 DE (FC | DC) D9 D9 CF D8 CE CE }
		$a189 = { (F9 | D9) DB CA (EE | CE) CC D1 DD (FF | DF) DA DA CC DB CD CD }
		$a190 = { (F8 | D8) DA CB (EF | CF) CD D0 DC (FE | DE) DB DB CD DA CC CC }
		$a191 = { (87 | A7) A5 B4 (90 | B0) B2 AF A3 (81 | A1) A4 A4 B2 A5 B3 B3 }
		$a192 = { (86 | A6) A4 B5 (91 | B1) B3 AE A2 (80 | A0) A5 A5 B3 A4 B2 B2 }
		$a193 = { (85 | A5) A7 B6 (92 | B2) B0 AD A1 (83 | A3) A6 A6 B0 A7 B1 B1 }
		$a194 = { (84 | A4) A6 B7 (93 | B3) B1 AC A0 (82 | A2) A7 A7 B1 A6 B0 B0 }
		$a195 = { (83 | A3) A1 B0 (94 | B4) B6 AB A7 (85 | A5) A0 A0 B6 A1 B7 B7 }
		$a196 = { (82 | A2) A0 B1 (95 | B5) B7 AA A6 (84 | A4) A1 A1 B7 A0 B6 B6 }
		$a197 = { (81 | A1) A3 B2 (96 | B6) B4 A9 A5 (87 | A7) A2 A2 B4 A3 B5 B5 }
		$a198 = { (80 | A0) A2 B3 (97 | B7) B5 A8 A4 (86 | A6) A3 A3 B5 A2 B4 B4 }
		$a199 = { (8F | AF) AD BC (98 | B8) BA A7 AB (89 | A9) AC AC BA AD BB BB }
		$a200 = { (8E | AE) AC BD (99 | B9) BB A6 AA (88 | A8) AD AD BB AC BA BA }
		$a201 = { (8D | AD) AF BE (9A | BA) B8 A5 A9 (8B | AB) AE AE B8 AF B9 B9 }
		$a202 = { (8C | AC) AE BF (9B | BB) B9 A4 A8 (8A | AA) AF AF B9 AE B8 B8 }
		$a203 = { (8B | AB) A9 B8 (9C | BC) BE A3 AF (8D | AD) A8 A8 BE A9 BF BF }
		$a204 = { (8A | AA) A8 B9 (9D | BD) BF A2 AE (8C | AC) A9 A9 BF A8 BE BE }
		$a205 = { (89 | A9) AB BA (9E | BE) BC A1 AD (8F | AF) AA AA BC AB BD BD }
		$a206 = { (88 | A8) AA BB (9F | BF) BD A0 AC (8E | AE) AB AB BD AA BC BC }
		$a207 = { (97 | B7) B5 A4 (80 | A0) A2 BF B3 (91 | B1) B4 B4 A2 B5 A3 A3 }
		$a208 = { (96 | B6) B4 A5 (81 | A1) A3 BE B2 (90 | B0) B5 B5 A3 B4 A2 A2 }
		$a209 = { (95 | B5) B7 A6 (82 | A2) A0 BD B1 (93 | B3) B6 B6 A0 B7 A1 A1 }
		$a210 = { (94 | B4) B6 A7 (83 | A3) A1 BC B0 (92 | B2) B7 B7 A1 B6 A0 A0 }
		$a211 = { (93 | B3) B1 A0 (84 | A4) A6 BB B7 (95 | B5) B0 B0 A6 B1 A7 A7 }
		$a212 = { (92 | B2) B0 A1 (85 | A5) A7 BA B6 (94 | B4) B1 B1 A7 B0 A6 A6 }
		$a213 = { (91 | B1) B3 A2 (86 | A6) A4 B9 B5 (97 | B7) B2 B2 A4 B3 A5 A5 }
		$a214 = { (90 | B0) B2 A3 (87 | A7) A5 B8 B4 (96 | B6) B3 B3 A5 B2 A4 A4 }
		$a215 = { (9F | BF) BD AC (88 | A8) AA B7 BB (99 | B9) BC BC AA BD AB AB }
		$a216 = { (9E | BE) BC AD (89 | A9) AB B6 BA (98 | B8) BD BD AB BC AA AA }
		$a217 = { (9D | BD) BF AE (8A | AA) A8 B5 B9 (9B | BB) BE BE A8 BF A9 A9 }
		$a218 = { (9C | BC) BE AF (8B | AB) A9 B4 B8 (9A | BA) BF BF A9 BE A8 A8 }
		$a219 = { (9B | BB) B9 A8 (8C | AC) AE B3 BF (9D | BD) B8 B8 AE B9 AF AF }
		$a220 = { (9A | BA) B8 A9 (8D | AD) AF B2 BE (9C | BC) B9 B9 AF B8 AE AE }
		$a221 = { (99 | B9) BB AA (8E | AE) AC B1 BD (9F | BF) BA BA AC BB AD AD }
		$a222 = { (98 | B8) BA AB (8F | AF) AD B0 BC (9E | BE) BB BB AD BA AC AC }
		$a223 = { (A7 | 87) 85 94 (B0 | 90) 92 8F 83 (A1 | 81) 84 84 92 85 93 93 }
		$a224 = { (A6 | 86) 84 95 (B1 | 91) 93 8E 82 (A0 | 80) 85 85 93 84 92 92 }
		$a225 = { (A5 | 85) 87 96 (B2 | 92) 90 8D 81 (A3 | 83) 86 86 90 87 91 91 }
		$a226 = { (A4 | 84) 86 97 (B3 | 93) 91 8C 80 (A2 | 82) 87 87 91 86 90 90 }
		$a227 = { (A3 | 83) 81 90 (B4 | 94) 96 8B 87 (A5 | 85) 80 80 96 81 97 97 }
		$a228 = { (A2 | 82) 80 91 (B5 | 95) 97 8A 86 (A4 | 84) 81 81 97 80 96 96 }
		$a229 = { (A1 | 81) 83 92 (B6 | 96) 94 89 85 (A7 | 87) 82 82 94 83 95 95 }
		$a230 = { (A0 | 80) 82 93 (B7 | 97) 95 88 84 (A6 | 86) 83 83 95 82 94 94 }
		$a231 = { (AF | 8F) 8D 9C (B8 | 98) 9A 87 8B (A9 | 89) 8C 8C 9A 8D 9B 9B }
		$a232 = { (AE | 8E) 8C 9D (B9 | 99) 9B 86 8A (A8 | 88) 8D 8D 9B 8C 9A 9A }
		$a233 = { (AD | 8D) 8F 9E (BA | 9A) 98 85 89 (AB | 8B) 8E 8E 98 8F 99 99 }
		$a234 = { (AC | 8C) 8E 9F (BB | 9B) 99 84 88 (AA | 8A) 8F 8F 99 8E 98 98 }
		$a235 = { (AB | 8B) 89 98 (BC | 9C) 9E 83 8F (AD | 8D) 88 88 9E 89 9F 9F }
		$a236 = { (AA | 8A) 88 99 (BD | 9D) 9F 82 8E (AC | 8C) 89 89 9F 88 9E 9E }
		$a237 = { (A9 | 89) 8B 9A (BE | 9E) 9C 81 8D (AF | 8F) 8A 8A 9C 8B 9D 9D }
		$a238 = { (A8 | 88) 8A 9B (BF | 9F) 9D 80 8C (AE | 8E) 8B 8B 9D 8A 9C 9C }
		$a239 = { (B7 | 97) 95 84 (A0 | 80) 82 9F 93 (B1 | 91) 94 94 82 95 83 83 }
		$a240 = { (B6 | 96) 94 85 (A1 | 81) 83 9E 92 (B0 | 90) 95 95 83 94 82 82 }
		$a241 = { (B5 | 95) 97 86 (A2 | 82) 80 9D 91 (B3 | 93) 96 96 80 97 81 81 }
		$a242 = { (B4 | 94) 96 87 (A3 | 83) 81 9C 90 (B2 | 92) 97 97 81 96 80 80 }
		$a243 = { (B3 | 93) 91 80 (A4 | 84) 86 9B 97 (B5 | 95) 90 90 86 91 87 87 }
		$a244 = { (B2 | 92) 90 81 (A5 | 85) 87 9A 96 (B4 | 94) 91 91 87 90 86 86 }
		$a245 = { (B1 | 91) 93 82 (A6 | 86) 84 99 95 (B7 | 97) 92 92 84 93 85 85 }
		$a246 = { (B0 | 90) 92 83 (A7 | 87) 85 98 94 (B6 | 96) 93 93 85 92 84 84 }
		$a247 = { (BF | 9F) 9D 8C (A8 | 88) 8A 97 9B (B9 | 99) 9C 9C 8A 9D 8B 8B }
		$a248 = { (BE | 9E) 9C 8D (A9 | 89) 8B 96 9A (B8 | 98) 9D 9D 8B 9C 8A 8A }
		$a249 = { (BD | 9D) 9F 8E (AA | 8A) 88 95 99 (BB | 9B) 9E 9E 88 9F 89 89 }
		$a250 = { (BC | 9C) 9E 8F (AB | 8B) 89 94 98 (BA | 9A) 9F 9F 89 9E 88 88 }
		$a251 = { (BB | 9B) 99 88 (AC | 8C) 8E 93 9F (BD | 9D) 98 98 8E 99 8F 8F }
		$a252 = { (BA | 9A) 98 89 (AD | 8D) 8F 92 9E (BC | 9C) 99 99 8F 98 8E 8E }
		$a253 = { (B9 | 99) 9B 8A (AE | 8E) 8C 91 9D (BF | 9F) 9A 9A 8C 9B 8D 8D }
		$a254 = { (4D | 6D) 6E 60 65 (4D | 6D) 68 63 73 60 73 78 }  // "LoadLibrary" XOR 0x01
		$a255 = { (4E | 6E) 6D 63 66 (4E | 6E) 6B 60 70 63 70 7B }  // "LoadLibrary" XOR 0x02
		$a256 = { (4F | 6F) 6C 62 67 (4F | 6F) 6A 61 71 62 71 7A }  // etc...
		$a257 = { (48 | 68) 6B 65 60 (48 | 68) 6D 66 76 65 76 7D }
		$a258 = { (49 | 69) 6A 64 61 (49 | 69) 6C 67 77 64 77 7C }
		$a259 = { (4A | 6A) 69 67 62 (4A | 6A) 6F 64 74 67 74 7F }
		$a260 = { (4B | 6B) 68 66 63 (4B | 6B) 6E 65 75 66 75 7E }
		$a261 = { (44 | 64) 67 69 6C (44 | 64) 61 6A 7A 69 7A 71 }
		$a262 = { (45 | 65) 66 68 6D (45 | 65) 60 6B 7B 68 7B 70 }
		$a263 = { (46 | 66) 65 6B 6E (46 | 66) 63 68 78 6B 78 73 }
		$a264 = { (47 | 67) 64 6A 6F (47 | 67) 62 69 79 6A 79 72 }
		$a265 = { (40 | 60) 63 6D 68 (40 | 60) 65 6E 7E 6D 7E 75 }
		$a266 = { (41 | 61) 62 6C 69 (41 | 61) 64 6F 7F 6C 7F 74 }
		$a267 = { (42 | 62) 61 6F 6A (42 | 62) 67 6C 7C 6F 7C 77 }
		$a268 = { (43 | 63) 60 6E 6B (43 | 63) 66 6D 7D 6E 7D 76 }
		$a269 = { (5C | 7C) 7F 71 74 (5C | 7C) 79 72 62 71 62 69 }
		$a270 = { (5D | 7D) 7E 70 75 (5D | 7D) 78 73 63 70 63 68 }
		$a271 = { (5E | 7E) 7D 73 76 (5E | 7E) 7B 70 60 73 60 6B }
		$a272 = { (5F | 7F) 7C 72 77 (5F | 7F) 7A 71 61 72 61 6A }
		$a273 = { (58 | 78) 7B 75 70 (58 | 78) 7D 76 66 75 66 6D }
		$a274 = { (59 | 79) 7A 74 71 (59 | 79) 7C 77 67 74 67 6C }
		$a275 = { (5A | 7A) 79 77 72 (5A | 7A) 7F 74 64 77 64 6F }
		$a276 = { (5B | 7B) 78 76 73 (5B | 7B) 7E 75 65 76 65 6E }
		$a277 = { (54 | 74) 77 79 7C (54 | 74) 71 7A 6A 79 6A 61 }
		$a278 = { (55 | 75) 76 78 7D (55 | 75) 70 7B 6B 78 6B 60 }
		$a279 = { (56 | 76) 75 7B 7E (56 | 76) 73 78 68 7B 68 63 }
		$a280 = { (57 | 77) 74 7A 7F (57 | 77) 72 79 69 7A 69 62 }
		$a281 = { (50 | 70) 73 7D 78 (50 | 70) 75 7E 6E 7D 6E 65 }
		$a282 = { (51 | 71) 72 7C 79 (51 | 71) 74 7F 6F 7C 6F 64 }
		$a283 = { (52 | 72) 71 7F 7A (52 | 72) 77 7C 6C 7F 6C 67 }
		$a284 = { (53 | 73) 70 7E 7B (53 | 73) 76 7D 6D 7E 6D 66 }
		// XOR 0x20 removed because it toggles capitalization and causes [lL]OAD[Ll]IBRARY to match.
		$a286 = { (6D | 4D) 4E 40 45 (6D | 4D) 48 43 53 40 53 58 }
		$a287 = { (6E | 4E) 4D 43 46 (6E | 4E) 4B 40 50 43 50 5B }
		$a288 = { (6F | 4F) 4C 42 47 (6F | 4F) 4A 41 51 42 51 5A }
		$a289 = { (68 | 48) 4B 45 40 (68 | 48) 4D 46 56 45 56 5D }
		$a290 = { (69 | 49) 4A 44 41 (69 | 49) 4C 47 57 44 57 5C }
		$a291 = { (6A | 4A) 49 47 42 (6A | 4A) 4F 44 54 47 54 5F }
		$a292 = { (6B | 4B) 48 46 43 (6B | 4B) 4E 45 55 46 55 5E }
		$a293 = { (64 | 44) 47 49 4C (64 | 44) 41 4A 5A 49 5A 51 }
		$a294 = { (65 | 45) 46 48 4D (65 | 45) 40 4B 5B 48 5B 50 }
		$a295 = { (66 | 46) 45 4B 4E (66 | 46) 43 48 58 4B 58 53 }
		$a296 = { (67 | 47) 44 4A 4F (67 | 47) 42 49 59 4A 59 52 }
		$a297 = { (60 | 40) 43 4D 48 (60 | 40) 45 4E 5E 4D 5E 55 }
		$a298 = { (61 | 41) 42 4C 49 (61 | 41) 44 4F 5F 4C 5F 54 }
		$a299 = { (62 | 42) 41 4F 4A (62 | 42) 47 4C 5C 4F 5C 57 }
		$a300 = { (63 | 43) 40 4E 4B (63 | 43) 46 4D 5D 4E 5D 56 }
		$a301 = { (7C | 5C) 5F 51 54 (7C | 5C) 59 52 42 51 42 49 }
		$a302 = { (7D | 5D) 5E 50 55 (7D | 5D) 58 53 43 50 43 48 }
		$a303 = { (7E | 5E) 5D 53 56 (7E | 5E) 5B 50 40 53 40 4B }
		$a304 = { (7F | 5F) 5C 52 57 (7F | 5F) 5A 51 41 52 41 4A }
		$a305 = { (78 | 58) 5B 55 50 (78 | 58) 5D 56 46 55 46 4D }
		$a306 = { (79 | 59) 5A 54 51 (79 | 59) 5C 57 47 54 47 4C }
		$a307 = { (7A | 5A) 59 57 52 (7A | 5A) 5F 54 44 57 44 4F }
		$a308 = { (7B | 5B) 58 56 53 (7B | 5B) 5E 55 45 56 45 4E }
		$a309 = { (74 | 54) 57 59 5C (74 | 54) 51 5A 4A 59 4A 41 }
		$a310 = { (75 | 55) 56 58 5D (75 | 55) 50 5B 4B 58 4B 40 }
		$a311 = { (76 | 56) 55 5B 5E (76 | 56) 53 58 48 5B 48 43 }
		$a312 = { (77 | 57) 54 5A 5F (77 | 57) 52 59 49 5A 49 42 }
		$a313 = { (70 | 50) 53 5D 58 (70 | 50) 55 5E 4E 5D 4E 45 }
		$a314 = { (71 | 51) 52 5C 59 (71 | 51) 54 5F 4F 5C 4F 44 }
		$a315 = { (72 | 52) 51 5F 5A (72 | 52) 57 5C 4C 5F 4C 47 }
		$a316 = { (73 | 53) 50 5E 5B (73 | 53) 56 5D 4D 5E 4D 46 }
		$a317 = { (0C | 2C) 2F 21 24 (0C | 2C) 29 22 32 21 32 39 }
		$a318 = { (0D | 2D) 2E 20 25 (0D | 2D) 28 23 33 20 33 38 }
		$a319 = { (0E | 2E) 2D 23 26 (0E | 2E) 2B 20 30 23 30 3B }
		$a320 = { (0F | 2F) 2C 22 27 (0F | 2F) 2A 21 31 22 31 3A }
		$a321 = { (08 | 28) 2B 25 20 (08 | 28) 2D 26 36 25 36 3D }
		$a322 = { (09 | 29) 2A 24 21 (09 | 29) 2C 27 37 24 37 3C }
		$a323 = { (0A | 2A) 29 27 22 (0A | 2A) 2F 24 34 27 34 3F }
		$a324 = { (0B | 2B) 28 26 23 (0B | 2B) 2E 25 35 26 35 3E }
		$a325 = { (04 | 24) 27 29 2C (04 | 24) 21 2A 3A 29 3A 31 }
		$a326 = { (05 | 25) 26 28 2D (05 | 25) 20 2B 3B 28 3B 30 }
		$a327 = { (06 | 26) 25 2B 2E (06 | 26) 23 28 38 2B 38 33 }
		$a328 = { (07 | 27) 24 2A 2F (07 | 27) 22 29 39 2A 39 32 }
		$a329 = { (00 | 20) 23 2D 28 (00 | 20) 25 2E 3E 2D 3E 35 }
		$a330 = { (01 | 21) 22 2C 29 (01 | 21) 24 2F 3F 2C 3F 34 }
		$a331 = { (02 | 22) 21 2F 2A (02 | 22) 27 2C 3C 2F 3C 37 }
		$a332 = { (03 | 23) 20 2E 2B (03 | 23) 26 2D 3D 2E 3D 36 }
		$a333 = { (1C | 3C) 3F 31 34 (1C | 3C) 39 32 22 31 22 29 }
		$a334 = { (1D | 3D) 3E 30 35 (1D | 3D) 38 33 23 30 23 28 }
		$a335 = { (1E | 3E) 3D 33 36 (1E | 3E) 3B 30 20 33 20 2B }
		$a336 = { (1F | 3F) 3C 32 37 (1F | 3F) 3A 31 21 32 21 2A }
		$a337 = { (18 | 38) 3B 35 30 (18 | 38) 3D 36 26 35 26 2D }
		$a338 = { (19 | 39) 3A 34 31 (19 | 39) 3C 37 27 34 27 2C }
		$a339 = { (1A | 3A) 39 37 32 (1A | 3A) 3F 34 24 37 24 2F }
		$a340 = { (1B | 3B) 38 36 33 (1B | 3B) 3E 35 25 36 25 2E }
		$a341 = { (14 | 34) 37 39 3C (14 | 34) 31 3A 2A 39 2A 21 }
		$a342 = { (15 | 35) 36 38 3D (15 | 35) 30 3B 2B 38 2B 20 }
		$a343 = { (16 | 36) 35 3B 3E (16 | 36) 33 38 28 3B 28 23 }
		$a344 = { (17 | 37) 34 3A 3F (17 | 37) 32 39 29 3A 29 22 }
		$a345 = { (10 | 30) 33 3D 38 (10 | 30) 35 3E 2E 3D 2E 25 }
		$a346 = { (11 | 31) 32 3C 39 (11 | 31) 34 3F 2F 3C 2F 24 }
		$a347 = { (12 | 32) 31 3F 3A (12 | 32) 37 3C 2C 3F 2C 27 }
		$a348 = { (13 | 33) 30 3E 3B (13 | 33) 36 3D 2D 3E 2D 26 }
		$a349 = { (2C | 0C) 0F 01 04 (2C | 0C) 09 02 12 01 12 19 }
		$a350 = { (2D | 0D) 0E 00 05 (2D | 0D) 08 03 13 00 13 18 }
		$a351 = { (2E | 0E) 0D 03 06 (2E | 0E) 0B 00 10 03 10 1B }
		$a352 = { (2F | 0F) 0C 02 07 (2F | 0F) 0A 01 11 02 11 1A }
		$a353 = { (28 | 08) 0B 05 00 (28 | 08) 0D 06 16 05 16 1D }
		$a354 = { (29 | 09) 0A 04 01 (29 | 09) 0C 07 17 04 17 1C }
		$a355 = { (2A | 0A) 09 07 02 (2A | 0A) 0F 04 14 07 14 1F }
		$a356 = { (2B | 0B) 08 06 03 (2B | 0B) 0E 05 15 06 15 1E }
		$a357 = { (24 | 04) 07 09 0C (24 | 04) 01 0A 1A 09 1A 11 }
		$a358 = { (25 | 05) 06 08 0D (25 | 05) 00 0B 1B 08 1B 10 }
		$a359 = { (26 | 06) 05 0B 0E (26 | 06) 03 08 18 0B 18 13 }
		$a360 = { (27 | 07) 04 0A 0F (27 | 07) 02 09 19 0A 19 12 }
		$a361 = { (20 | 00) 03 0D 08 (20 | 00) 05 0E 1E 0D 1E 15 }
		$a362 = { (21 | 01) 02 0C 09 (21 | 01) 04 0F 1F 0C 1F 14 }
		$a363 = { (22 | 02) 01 0F 0A (22 | 02) 07 0C 1C 0F 1C 17 }
		$a364 = { (23 | 03) 00 0E 0B (23 | 03) 06 0D 1D 0E 1D 16 }
		$a365 = { (3C | 1C) 1F 11 14 (3C | 1C) 19 12 02 11 02 09 }
		$a366 = { (3D | 1D) 1E 10 15 (3D | 1D) 18 13 03 10 03 08 }
		$a367 = { (3E | 1E) 1D 13 16 (3E | 1E) 1B 10 00 13 00 0B }
		$a368 = { (3F | 1F) 1C 12 17 (3F | 1F) 1A 11 01 12 01 0A }
		$a369 = { (38 | 18) 1B 15 10 (38 | 18) 1D 16 06 15 06 0D }
		$a370 = { (39 | 19) 1A 14 11 (39 | 19) 1C 17 07 14 07 0C }
		$a371 = { (3A | 1A) 19 17 12 (3A | 1A) 1F 14 04 17 04 0F }
		$a372 = { (3B | 1B) 18 16 13 (3B | 1B) 1E 15 05 16 05 0E }
		$a373 = { (34 | 14) 17 19 1C (34 | 14) 11 1A 0A 19 0A 01 }
		$a374 = { (35 | 15) 16 18 1D (35 | 15) 10 1B 0B 18 0B 00 }
		$a375 = { (36 | 16) 15 1B 1E (36 | 16) 13 18 08 1B 08 03 }
		$a376 = { (37 | 17) 14 1A 1F (37 | 17) 12 19 09 1A 09 02 }
		$a377 = { (30 | 10) 13 1D 18 (30 | 10) 15 1E 0E 1D 0E 05 }
		$a378 = { (31 | 11) 12 1C 19 (31 | 11) 14 1F 0F 1C 0F 04 }
		$a379 = { (32 | 12) 11 1F 1A (32 | 12) 17 1C 0C 1F 0C 07 }
		$a380 = { (33 | 13) 10 1E 1B (33 | 13) 16 1D 0D 1E 0D 06 }
		$a381 = { (CC | EC) EF E1 E4 (CC | EC) E9 E2 F2 E1 F2 F9 }
		$a382 = { (CD | ED) EE E0 E5 (CD | ED) E8 E3 F3 E0 F3 F8 }
		$a383 = { (CE | EE) ED E3 E6 (CE | EE) EB E0 F0 E3 F0 FB }
		$a384 = { (CF | EF) EC E2 E7 (CF | EF) EA E1 F1 E2 F1 FA }
		$a385 = { (C8 | E8) EB E5 E0 (C8 | E8) ED E6 F6 E5 F6 FD }
		$a386 = { (C9 | E9) EA E4 E1 (C9 | E9) EC E7 F7 E4 F7 FC }
		$a387 = { (CA | EA) E9 E7 E2 (CA | EA) EF E4 F4 E7 F4 FF }
		$a388 = { (CB | EB) E8 E6 E3 (CB | EB) EE E5 F5 E6 F5 FE }
		$a389 = { (C4 | E4) E7 E9 EC (C4 | E4) E1 EA FA E9 FA F1 }
		$a390 = { (C5 | E5) E6 E8 ED (C5 | E5) E0 EB FB E8 FB F0 }
		$a391 = { (C6 | E6) E5 EB EE (C6 | E6) E3 E8 F8 EB F8 F3 }
		$a392 = { (C7 | E7) E4 EA EF (C7 | E7) E2 E9 F9 EA F9 F2 }
		$a393 = { (C0 | E0) E3 ED E8 (C0 | E0) E5 EE FE ED FE F5 }
		$a394 = { (C1 | E1) E2 EC E9 (C1 | E1) E4 EF FF EC FF F4 }
		$a395 = { (C2 | E2) E1 EF EA (C2 | E2) E7 EC FC EF FC F7 }
		$a396 = { (C3 | E3) E0 EE EB (C3 | E3) E6 ED FD EE FD F6 }
		$a397 = { (DC | FC) FF F1 F4 (DC | FC) F9 F2 E2 F1 E2 E9 }
		$a398 = { (DD | FD) FE F0 F5 (DD | FD) F8 F3 E3 F0 E3 E8 }
		$a399 = { (DE | FE) FD F3 F6 (DE | FE) FB F0 E0 F3 E0 EB }
		$a400 = { (DF | FF) FC F2 F7 (DF | FF) FA F1 E1 F2 E1 EA }
		$a401 = { (D8 | F8) FB F5 F0 (D8 | F8) FD F6 E6 F5 E6 ED }
		$a402 = { (D9 | F9) FA F4 F1 (D9 | F9) FC F7 E7 F4 E7 EC }
		$a403 = { (DA | FA) F9 F7 F2 (DA | FA) FF F4 E4 F7 E4 EF }
		$a404 = { (DB | FB) F8 F6 F3 (DB | FB) FE F5 E5 F6 E5 EE }
		$a405 = { (D4 | F4) F7 F9 FC (D4 | F4) F1 FA EA F9 EA E1 }
		$a406 = { (D5 | F5) F6 F8 FD (D5 | F5) F0 FB EB F8 EB E0 }
		$a407 = { (D6 | F6) F5 FB FE (D6 | F6) F3 F8 E8 FB E8 E3 }
		$a408 = { (D7 | F7) F4 FA FF (D7 | F7) F2 F9 E9 FA E9 E2 }
		$a409 = { (D0 | F0) F3 FD F8 (D0 | F0) F5 FE EE FD EE E5 }
		$a410 = { (D1 | F1) F2 FC F9 (D1 | F1) F4 FF EF FC EF E4 }
		$a411 = { (D2 | F2) F1 FF FA (D2 | F2) F7 FC EC FF EC E7 }
		$a412 = { (D3 | F3) F0 FE FB (D3 | F3) F6 FD ED FE ED E6 }
		$a413 = { (EC | CC) CF C1 C4 (EC | CC) C9 C2 D2 C1 D2 D9 }
		$a414 = { (ED | CD) CE C0 C5 (ED | CD) C8 C3 D3 C0 D3 D8 }
		$a415 = { (EE | CE) CD C3 C6 (EE | CE) CB C0 D0 C3 D0 DB }
		$a416 = { (EF | CF) CC C2 C7 (EF | CF) CA C1 D1 C2 D1 DA }
		$a417 = { (E8 | C8) CB C5 C0 (E8 | C8) CD C6 D6 C5 D6 DD }
		$a418 = { (E9 | C9) CA C4 C1 (E9 | C9) CC C7 D7 C4 D7 DC }
		$a419 = { (EA | CA) C9 C7 C2 (EA | CA) CF C4 D4 C7 D4 DF }
		$a420 = { (EB | CB) C8 C6 C3 (EB | CB) CE C5 D5 C6 D5 DE }
		$a421 = { (E4 | C4) C7 C9 CC (E4 | C4) C1 CA DA C9 DA D1 }
		$a422 = { (E5 | C5) C6 C8 CD (E5 | C5) C0 CB DB C8 DB D0 }
		$a423 = { (E6 | C6) C5 CB CE (E6 | C6) C3 C8 D8 CB D8 D3 }
		$a424 = { (E7 | C7) C4 CA CF (E7 | C7) C2 C9 D9 CA D9 D2 }
		$a425 = { (E0 | C0) C3 CD C8 (E0 | C0) C5 CE DE CD DE D5 }
		$a426 = { (E1 | C1) C2 CC C9 (E1 | C1) C4 CF DF CC DF D4 }
		$a427 = { (E2 | C2) C1 CF CA (E2 | C2) C7 CC DC CF DC D7 }
		$a428 = { (E3 | C3) C0 CE CB (E3 | C3) C6 CD DD CE DD D6 }
		$a429 = { (FC | DC) DF D1 D4 (FC | DC) D9 D2 C2 D1 C2 C9 }
		$a430 = { (FD | DD) DE D0 D5 (FD | DD) D8 D3 C3 D0 C3 C8 }
		$a431 = { (FE | DE) DD D3 D6 (FE | DE) DB D0 C0 D3 C0 CB }
		$a432 = { (FF | DF) DC D2 D7 (FF | DF) DA D1 C1 D2 C1 CA }
		$a433 = { (F8 | D8) DB D5 D0 (F8 | D8) DD D6 C6 D5 C6 CD }
		$a434 = { (F9 | D9) DA D4 D1 (F9 | D9) DC D7 C7 D4 C7 CC }
		$a435 = { (FA | DA) D9 D7 D2 (FA | DA) DF D4 C4 D7 C4 CF }
		$a436 = { (FB | DB) D8 D6 D3 (FB | DB) DE D5 C5 D6 C5 CE }
		$a437 = { (F4 | D4) D7 D9 DC (F4 | D4) D1 DA CA D9 CA C1 }
		$a438 = { (F5 | D5) D6 D8 DD (F5 | D5) D0 DB CB D8 CB C0 }
		$a439 = { (F6 | D6) D5 DB DE (F6 | D6) D3 D8 C8 DB C8 C3 }
		$a440 = { (F7 | D7) D4 DA DF (F7 | D7) D2 D9 C9 DA C9 C2 }
		$a441 = { (F0 | D0) D3 DD D8 (F0 | D0) D5 DE CE DD CE C5 }
		$a442 = { (F1 | D1) D2 DC D9 (F1 | D1) D4 DF CF DC CF C4 }
		$a443 = { (F2 | D2) D1 DF DA (F2 | D2) D7 DC CC DF CC C7 }
		$a444 = { (F3 | D3) D0 DE DB (F3 | D3) D6 DD CD DE CD C6 }
		$a445 = { (8C | AC) AF A1 A4 (8C | AC) A9 A2 B2 A1 B2 B9 }
		$a446 = { (8D | AD) AE A0 A5 (8D | AD) A8 A3 B3 A0 B3 B8 }
		$a447 = { (8E | AE) AD A3 A6 (8E | AE) AB A0 B0 A3 B0 BB }
		$a448 = { (8F | AF) AC A2 A7 (8F | AF) AA A1 B1 A2 B1 BA }
		$a449 = { (88 | A8) AB A5 A0 (88 | A8) AD A6 B6 A5 B6 BD }
		$a450 = { (89 | A9) AA A4 A1 (89 | A9) AC A7 B7 A4 B7 BC }
		$a451 = { (8A | AA) A9 A7 A2 (8A | AA) AF A4 B4 A7 B4 BF }
		$a452 = { (8B | AB) A8 A6 A3 (8B | AB) AE A5 B5 A6 B5 BE }
		$a453 = { (84 | A4) A7 A9 AC (84 | A4) A1 AA BA A9 BA B1 }
		$a454 = { (85 | A5) A6 A8 AD (85 | A5) A0 AB BB A8 BB B0 }
		$a455 = { (86 | A6) A5 AB AE (86 | A6) A3 A8 B8 AB B8 B3 }
		$a456 = { (87 | A7) A4 AA AF (87 | A7) A2 A9 B9 AA B9 B2 }
		$a457 = { (80 | A0) A3 AD A8 (80 | A0) A5 AE BE AD BE B5 }
		$a458 = { (81 | A1) A2 AC A9 (81 | A1) A4 AF BF AC BF B4 }
		$a459 = { (82 | A2) A1 AF AA (82 | A2) A7 AC BC AF BC B7 }
		$a460 = { (83 | A3) A0 AE AB (83 | A3) A6 AD BD AE BD B6 }
		$a461 = { (9C | BC) BF B1 B4 (9C | BC) B9 B2 A2 B1 A2 A9 }
		$a462 = { (9D | BD) BE B0 B5 (9D | BD) B8 B3 A3 B0 A3 A8 }
		$a463 = { (9E | BE) BD B3 B6 (9E | BE) BB B0 A0 B3 A0 AB }
		$a464 = { (9F | BF) BC B2 B7 (9F | BF) BA B1 A1 B2 A1 AA }
		$a465 = { (98 | B8) BB B5 B0 (98 | B8) BD B6 A6 B5 A6 AD }
		$a466 = { (99 | B9) BA B4 B1 (99 | B9) BC B7 A7 B4 A7 AC }
		$a467 = { (9A | BA) B9 B7 B2 (9A | BA) BF B4 A4 B7 A4 AF }
		$a468 = { (9B | BB) B8 B6 B3 (9B | BB) BE B5 A5 B6 A5 AE }
		$a469 = { (94 | B4) B7 B9 BC (94 | B4) B1 BA AA B9 AA A1 }
		$a470 = { (95 | B5) B6 B8 BD (95 | B5) B0 BB AB B8 AB A0 }
		$a471 = { (96 | B6) B5 BB BE (96 | B6) B3 B8 A8 BB A8 A3 }
		$a472 = { (97 | B7) B4 BA BF (97 | B7) B2 B9 A9 BA A9 A2 }
		$a473 = { (90 | B0) B3 BD B8 (90 | B0) B5 BE AE BD AE A5 }
		$a474 = { (91 | B1) B2 BC B9 (91 | B1) B4 BF AF BC AF A4 }
		$a475 = { (92 | B2) B1 BF BA (92 | B2) B7 BC AC BF AC A7 }
		$a476 = { (93 | B3) B0 BE BB (93 | B3) B6 BD AD BE AD A6 }
		$a477 = { (AC | 8C) 8F 81 84 (AC | 8C) 89 82 92 81 92 99 }
		$a478 = { (AD | 8D) 8E 80 85 (AD | 8D) 88 83 93 80 93 98 }
		$a479 = { (AE | 8E) 8D 83 86 (AE | 8E) 8B 80 90 83 90 9B }
		$a480 = { (AF | 8F) 8C 82 87 (AF | 8F) 8A 81 91 82 91 9A }
		$a481 = { (A8 | 88) 8B 85 80 (A8 | 88) 8D 86 96 85 96 9D }
		$a482 = { (A9 | 89) 8A 84 81 (A9 | 89) 8C 87 97 84 97 9C }
		$a483 = { (AA | 8A) 89 87 82 (AA | 8A) 8F 84 94 87 94 9F }
		$a484 = { (AB | 8B) 88 86 83 (AB | 8B) 8E 85 95 86 95 9E }
		$a485 = { (A4 | 84) 87 89 8C (A4 | 84) 81 8A 9A 89 9A 91 }
		$a486 = { (A5 | 85) 86 88 8D (A5 | 85) 80 8B 9B 88 9B 90 }
		$a487 = { (A6 | 86) 85 8B 8E (A6 | 86) 83 88 98 8B 98 93 }
		$a488 = { (A7 | 87) 84 8A 8F (A7 | 87) 82 89 99 8A 99 92 }
		$a489 = { (A0 | 80) 83 8D 88 (A0 | 80) 85 8E 9E 8D 9E 95 }
		$a490 = { (A1 | 81) 82 8C 89 (A1 | 81) 84 8F 9F 8C 9F 94 }
		$a491 = { (A2 | 82) 81 8F 8A (A2 | 82) 87 8C 9C 8F 9C 97 }
		$a492 = { (A3 | 83) 80 8E 8B (A3 | 83) 86 8D 9D 8E 9D 96 }
		$a493 = { (BC | 9C) 9F 91 94 (BC | 9C) 99 92 82 91 82 89 }
		$a494 = { (BD | 9D) 9E 90 95 (BD | 9D) 98 93 83 90 83 88 }
		$a495 = { (BE | 9E) 9D 93 96 (BE | 9E) 9B 90 80 93 80 8B }
		$a496 = { (BF | 9F) 9C 92 97 (BF | 9F) 9A 91 81 92 81 8A }
		$a497 = { (B8 | 98) 9B 95 90 (B8 | 98) 9D 96 86 95 86 8D }
		$a498 = { (B9 | 99) 9A 94 91 (B9 | 99) 9C 97 87 94 87 8C }
		$a499 = { (BA | 9A) 99 97 92 (BA | 9A) 9F 94 84 97 84 8F }
		$a500 = { (BB | 9B) 98 96 93 (BB | 9B) 9E 95 85 96 85 8E }
		$a501 = { (B4 | 94) 97 99 9C (B4 | 94) 91 9A 8A 99 8A 81 }
		$a502 = { (B5 | 95) 96 98 9D (B5 | 95) 90 9B 8B 98 8B 80 }
		$a503 = { (B6 | 96) 95 9B 9E (B6 | 96) 93 98 88 9B 88 83 }
		$a504 = { (B7 | 97) 94 9A 9F (B7 | 97) 92 99 89 9A 89 82 }
		$a505 = { (B0 | 90) 93 9D 98 (B0 | 90) 95 9E 8E 9D 8E 85 }
		$a506 = { (B1 | 91) 92 9C 99 (B1 | 91) 94 9F 8F 9C 8F 84 }
		$a507 = { (B2 | 92) 91 9F 9A (B2 | 92) 97 9C 8C 9F 8C 87 }
	condition:
		any of them
}

rule Xored_PE
{
	meta:
		description = "Contains a XORed PE executable"
		author = "Ivan Kwiatkowski (@JusticeRage)"
		
	strings:
		$a0 = { 55 69 68 72 21 71 73 6E 66 73 60 6C 21 62 60 6F 6F 6E 75 21 63 64 21 73 74 6F 21 68 6F 21 45 4E 52 21 6C 6E 65 64 2F }
		$a1 = { 56 6A 6B 71 22 72 70 6D 65 70 63 6F 22 61 63 6C 6C 6D 76 22 60 67 22 70 77 6C 22 6B 6C 22 46 4D 51 22 6F 6D 66 67 2C }
		$a2 = { 57 6B 6A 70 23 73 71 6C 64 71 62 6E 23 60 62 6D 6D 6C 77 23 61 66 23 71 76 6D 23 6A 6D 23 47 4C 50 23 6E 6C 67 66 2D }
		$a3 = { 50 6C 6D 77 24 74 76 6B 63 76 65 69 24 67 65 6A 6A 6B 70 24 66 61 24 76 71 6A 24 6D 6A 24 40 4B 57 24 69 6B 60 61 2A }
		$a4 = { 51 6D 6C 76 25 75 77 6A 62 77 64 68 25 66 64 6B 6B 6A 71 25 67 60 25 77 70 6B 25 6C 6B 25 41 4A 56 25 68 6A 61 60 2B }
		$a5 = { 52 6E 6F 75 26 76 74 69 61 74 67 6B 26 65 67 68 68 69 72 26 64 63 26 74 73 68 26 6F 68 26 42 49 55 26 6B 69 62 63 28 }
		$a6 = { 53 6F 6E 74 27 77 75 68 60 75 66 6A 27 64 66 69 69 68 73 27 65 62 27 75 72 69 27 6E 69 27 43 48 54 27 6A 68 63 62 29 }
		$a7 = { 5C 60 61 7B 28 78 7A 67 6F 7A 69 65 28 6B 69 66 66 67 7C 28 6A 6D 28 7A 7D 66 28 61 66 28 4C 47 5B 28 65 67 6C 6D 26 }
		$a8 = { 5D 61 60 7A 29 79 7B 66 6E 7B 68 64 29 6A 68 67 67 66 7D 29 6B 6C 29 7B 7C 67 29 60 67 29 4D 46 5A 29 64 66 6D 6C 27 }
		$a9 = { 5E 62 63 79 2A 7A 78 65 6D 78 6B 67 2A 69 6B 64 64 65 7E 2A 68 6F 2A 78 7F 64 2A 63 64 2A 4E 45 59 2A 67 65 6E 6F 24 }
		$a10 = { 5F 63 62 78 2B 7B 79 64 6C 79 6A 66 2B 68 6A 65 65 64 7F 2B 69 6E 2B 79 7E 65 2B 62 65 2B 4F 44 58 2B 66 64 6F 6E 25 }
		$a11 = { 58 64 65 7F 2C 7C 7E 63 6B 7E 6D 61 2C 6F 6D 62 62 63 78 2C 6E 69 2C 7E 79 62 2C 65 62 2C 48 43 5F 2C 61 63 68 69 22 }
		$a12 = { 59 65 64 7E 2D 7D 7F 62 6A 7F 6C 60 2D 6E 6C 63 63 62 79 2D 6F 68 2D 7F 78 63 2D 64 63 2D 49 42 5E 2D 60 62 69 68 23 }
		$a13 = { 5A 66 67 7D 2E 7E 7C 61 69 7C 6F 63 2E 6D 6F 60 60 61 7A 2E 6C 6B 2E 7C 7B 60 2E 67 60 2E 4A 41 5D 2E 63 61 6A 6B 20 }
		$a14 = { 5B 67 66 7C 2F 7F 7D 60 68 7D 6E 62 2F 6C 6E 61 61 60 7B 2F 6D 6A 2F 7D 7A 61 2F 66 61 2F 4B 40 5C 2F 62 60 6B 6A 21 }
		$a15 = { 44 78 79 63 30 60 62 7F 77 62 71 7D 30 73 71 7E 7E 7F 64 30 72 75 30 62 65 7E 30 79 7E 30 54 5F 43 30 7D 7F 74 75 3E }
		$a16 = { 45 79 78 62 31 61 63 7E 76 63 70 7C 31 72 70 7F 7F 7E 65 31 73 74 31 63 64 7F 31 78 7F 31 55 5E 42 31 7C 7E 75 74 3F }
		$a17 = { 46 7A 7B 61 32 62 60 7D 75 60 73 7F 32 71 73 7C 7C 7D 66 32 70 77 32 60 67 7C 32 7B 7C 32 56 5D 41 32 7F 7D 76 77 3C }
		$a18 = { 47 7B 7A 60 33 63 61 7C 74 61 72 7E 33 70 72 7D 7D 7C 67 33 71 76 33 61 66 7D 33 7A 7D 33 57 5C 40 33 7E 7C 77 76 3D }
		$a19 = { 40 7C 7D 67 34 64 66 7B 73 66 75 79 34 77 75 7A 7A 7B 60 34 76 71 34 66 61 7A 34 7D 7A 34 50 5B 47 34 79 7B 70 71 3A }
		$a20 = { 41 7D 7C 66 35 65 67 7A 72 67 74 78 35 76 74 7B 7B 7A 61 35 77 70 35 67 60 7B 35 7C 7B 35 51 5A 46 35 78 7A 71 70 3B }
		$a21 = { 42 7E 7F 65 36 66 64 79 71 64 77 7B 36 75 77 78 78 79 62 36 74 73 36 64 63 78 36 7F 78 36 52 59 45 36 7B 79 72 73 38 }
		$a22 = { 43 7F 7E 64 37 67 65 78 70 65 76 7A 37 74 76 79 79 78 63 37 75 72 37 65 62 79 37 7E 79 37 53 58 44 37 7A 78 73 72 39 }
		$a23 = { 4C 70 71 6B 38 68 6A 77 7F 6A 79 75 38 7B 79 76 76 77 6C 38 7A 7D 38 6A 6D 76 38 71 76 38 5C 57 4B 38 75 77 7C 7D 36 }
		$a24 = { 4D 71 70 6A 39 69 6B 76 7E 6B 78 74 39 7A 78 77 77 76 6D 39 7B 7C 39 6B 6C 77 39 70 77 39 5D 56 4A 39 74 76 7D 7C 37 }
		$a25 = { 4E 72 73 69 3A 6A 68 75 7D 68 7B 77 3A 79 7B 74 74 75 6E 3A 78 7F 3A 68 6F 74 3A 73 74 3A 5E 55 49 3A 77 75 7E 7F 34 }
		$a26 = { 4F 73 72 68 3B 6B 69 74 7C 69 7A 76 3B 78 7A 75 75 74 6F 3B 79 7E 3B 69 6E 75 3B 72 75 3B 5F 54 48 3B 76 74 7F 7E 35 }
		$a27 = { 48 74 75 6F 3C 6C 6E 73 7B 6E 7D 71 3C 7F 7D 72 72 73 68 3C 7E 79 3C 6E 69 72 3C 75 72 3C 58 53 4F 3C 71 73 78 79 32 }
		$a28 = { 49 75 74 6E 3D 6D 6F 72 7A 6F 7C 70 3D 7E 7C 73 73 72 69 3D 7F 78 3D 6F 68 73 3D 74 73 3D 59 52 4E 3D 70 72 79 78 33 }
		$a29 = { 4A 76 77 6D 3E 6E 6C 71 79 6C 7F 73 3E 7D 7F 70 70 71 6A 3E 7C 7B 3E 6C 6B 70 3E 77 70 3E 5A 51 4D 3E 73 71 7A 7B 30 }
		$a30 = { 4B 77 76 6C 3F 6F 6D 70 78 6D 7E 72 3F 7C 7E 71 71 70 6B 3F 7D 7A 3F 6D 6A 71 3F 76 71 3F 5B 50 4C 3F 72 70 7B 7A 31 }
		$a32 = { 75 49 48 52 01 51 53 4E 46 53 40 4C 01 42 40 4F 4F 4E 55 01 43 44 01 53 54 4F 01 48 4F 01 65 6E 72 01 4C 4E 45 44 0F }
		$a33 = { 76 4A 4B 51 02 52 50 4D 45 50 43 4F 02 41 43 4C 4C 4D 56 02 40 47 02 50 57 4C 02 4B 4C 02 66 6D 71 02 4F 4D 46 47 0C }
		$a34 = { 77 4B 4A 50 03 53 51 4C 44 51 42 4E 03 40 42 4D 4D 4C 57 03 41 46 03 51 56 4D 03 4A 4D 03 67 6C 70 03 4E 4C 47 46 0D }
		$a35 = { 70 4C 4D 57 04 54 56 4B 43 56 45 49 04 47 45 4A 4A 4B 50 04 46 41 04 56 51 4A 04 4D 4A 04 60 6B 77 04 49 4B 40 41 0A }
		$a36 = { 71 4D 4C 56 05 55 57 4A 42 57 44 48 05 46 44 4B 4B 4A 51 05 47 40 05 57 50 4B 05 4C 4B 05 61 6A 76 05 48 4A 41 40 0B }
		$a37 = { 72 4E 4F 55 06 56 54 49 41 54 47 4B 06 45 47 48 48 49 52 06 44 43 06 54 53 48 06 4F 48 06 62 69 75 06 4B 49 42 43 08 }
		$a38 = { 73 4F 4E 54 07 57 55 48 40 55 46 4A 07 44 46 49 49 48 53 07 45 42 07 55 52 49 07 4E 49 07 63 68 74 07 4A 48 43 42 09 }
		$a39 = { 7C 40 41 5B 08 58 5A 47 4F 5A 49 45 08 4B 49 46 46 47 5C 08 4A 4D 08 5A 5D 46 08 41 46 08 6C 67 7B 08 45 47 4C 4D 06 }
		$a40 = { 7D 41 40 5A 09 59 5B 46 4E 5B 48 44 09 4A 48 47 47 46 5D 09 4B 4C 09 5B 5C 47 09 40 47 09 6D 66 7A 09 44 46 4D 4C 07 }
		$a41 = { 7E 42 43 59 0A 5A 58 45 4D 58 4B 47 0A 49 4B 44 44 45 5E 0A 48 4F 0A 58 5F 44 0A 43 44 0A 6E 65 79 0A 47 45 4E 4F 04 }
		$a42 = { 7F 43 42 58 0B 5B 59 44 4C 59 4A 46 0B 48 4A 45 45 44 5F 0B 49 4E 0B 59 5E 45 0B 42 45 0B 6F 64 78 0B 46 44 4F 4E 05 }
		$a43 = { 78 44 45 5F 0C 5C 5E 43 4B 5E 4D 41 0C 4F 4D 42 42 43 58 0C 4E 49 0C 5E 59 42 0C 45 42 0C 68 63 7F 0C 41 43 48 49 02 }
		$a44 = { 79 45 44 5E 0D 5D 5F 42 4A 5F 4C 40 0D 4E 4C 43 43 42 59 0D 4F 48 0D 5F 58 43 0D 44 43 0D 69 62 7E 0D 40 42 49 48 03 }
		$a45 = { 7A 46 47 5D 0E 5E 5C 41 49 5C 4F 43 0E 4D 4F 40 40 41 5A 0E 4C 4B 0E 5C 5B 40 0E 47 40 0E 6A 61 7D 0E 43 41 4A 4B 00 }
		$a46 = { 7B 47 46 5C 0F 5F 5D 40 48 5D 4E 42 0F 4C 4E 41 41 40 5B 0F 4D 4A 0F 5D 5A 41 0F 46 41 0F 6B 60 7C 0F 42 40 4B 4A 01 }
		$a47 = { 64 58 59 43 10 40 42 5F 57 42 51 5D 10 53 51 5E 5E 5F 44 10 52 55 10 42 45 5E 10 59 5E 10 74 7F 63 10 5D 5F 54 55 1E }
		$a48 = { 65 59 58 42 11 41 43 5E 56 43 50 5C 11 52 50 5F 5F 5E 45 11 53 54 11 43 44 5F 11 58 5F 11 75 7E 62 11 5C 5E 55 54 1F }
		$a49 = { 66 5A 5B 41 12 42 40 5D 55 40 53 5F 12 51 53 5C 5C 5D 46 12 50 57 12 40 47 5C 12 5B 5C 12 76 7D 61 12 5F 5D 56 57 1C }
		$a50 = { 67 5B 5A 40 13 43 41 5C 54 41 52 5E 13 50 52 5D 5D 5C 47 13 51 56 13 41 46 5D 13 5A 5D 13 77 7C 60 13 5E 5C 57 56 1D }
		$a51 = { 60 5C 5D 47 14 44 46 5B 53 46 55 59 14 57 55 5A 5A 5B 40 14 56 51 14 46 41 5A 14 5D 5A 14 70 7B 67 14 59 5B 50 51 1A }
		$a52 = { 61 5D 5C 46 15 45 47 5A 52 47 54 58 15 56 54 5B 5B 5A 41 15 57 50 15 47 40 5B 15 5C 5B 15 71 7A 66 15 58 5A 51 50 1B }
		$a53 = { 62 5E 5F 45 16 46 44 59 51 44 57 5B 16 55 57 58 58 59 42 16 54 53 16 44 43 58 16 5F 58 16 72 79 65 16 5B 59 52 53 18 }
		$a54 = { 63 5F 5E 44 17 47 45 58 50 45 56 5A 17 54 56 59 59 58 43 17 55 52 17 45 42 59 17 5E 59 17 73 78 64 17 5A 58 53 52 19 }
		$a55 = { 6C 50 51 4B 18 48 4A 57 5F 4A 59 55 18 5B 59 56 56 57 4C 18 5A 5D 18 4A 4D 56 18 51 56 18 7C 77 6B 18 55 57 5C 5D 16 }
		$a56 = { 6D 51 50 4A 19 49 4B 56 5E 4B 58 54 19 5A 58 57 57 56 4D 19 5B 5C 19 4B 4C 57 19 50 57 19 7D 76 6A 19 54 56 5D 5C 17 }
		$a57 = { 6E 52 53 49 1A 4A 48 55 5D 48 5B 57 1A 59 5B 54 54 55 4E 1A 58 5F 1A 48 4F 54 1A 53 54 1A 7E 75 69 1A 57 55 5E 5F 14 }
		$a58 = { 6F 53 52 48 1B 4B 49 54 5C 49 5A 56 1B 58 5A 55 55 54 4F 1B 59 5E 1B 49 4E 55 1B 52 55 1B 7F 74 68 1B 56 54 5F 5E 15 }
		$a59 = { 68 54 55 4F 1C 4C 4E 53 5B 4E 5D 51 1C 5F 5D 52 52 53 48 1C 5E 59 1C 4E 49 52 1C 55 52 1C 78 73 6F 1C 51 53 58 59 12 }
		$a60 = { 69 55 54 4E 1D 4D 4F 52 5A 4F 5C 50 1D 5E 5C 53 53 52 49 1D 5F 58 1D 4F 48 53 1D 54 53 1D 79 72 6E 1D 50 52 59 58 13 }
		$a61 = { 6A 56 57 4D 1E 4E 4C 51 59 4C 5F 53 1E 5D 5F 50 50 51 4A 1E 5C 5B 1E 4C 4B 50 1E 57 50 1E 7A 71 6D 1E 53 51 5A 5B 10 }
		$a62 = { 6B 57 56 4C 1F 4F 4D 50 58 4D 5E 52 1F 5C 5E 51 51 50 4B 1F 5D 5A 1F 4D 4A 51 1F 56 51 1F 7B 70 6C 1F 52 50 5B 5A 11 }
		$a63 = { 14 28 29 33 60 30 32 2F 27 32 21 2D 60 23 21 2E 2E 2F 34 60 22 25 60 32 35 2E 60 29 2E 60 04 0F 13 60 2D 2F 24 25 6E }
		$a64 = { 15 29 28 32 61 31 33 2E 26 33 20 2C 61 22 20 2F 2F 2E 35 61 23 24 61 33 34 2F 61 28 2F 61 05 0E 12 61 2C 2E 25 24 6F }
		$a65 = { 16 2A 2B 31 62 32 30 2D 25 30 23 2F 62 21 23 2C 2C 2D 36 62 20 27 62 30 37 2C 62 2B 2C 62 06 0D 11 62 2F 2D 26 27 6C }
		$a66 = { 17 2B 2A 30 63 33 31 2C 24 31 22 2E 63 20 22 2D 2D 2C 37 63 21 26 63 31 36 2D 63 2A 2D 63 07 0C 10 63 2E 2C 27 26 6D }
		$a67 = { 10 2C 2D 37 64 34 36 2B 23 36 25 29 64 27 25 2A 2A 2B 30 64 26 21 64 36 31 2A 64 2D 2A 64 00 0B 17 64 29 2B 20 21 6A }
		$a68 = { 11 2D 2C 36 65 35 37 2A 22 37 24 28 65 26 24 2B 2B 2A 31 65 27 20 65 37 30 2B 65 2C 2B 65 01 0A 16 65 28 2A 21 20 6B }
		$a69 = { 12 2E 2F 35 66 36 34 29 21 34 27 2B 66 25 27 28 28 29 32 66 24 23 66 34 33 28 66 2F 28 66 02 09 15 66 2B 29 22 23 68 }
		$a70 = { 13 2F 2E 34 67 37 35 28 20 35 26 2A 67 24 26 29 29 28 33 67 25 22 67 35 32 29 67 2E 29 67 03 08 14 67 2A 28 23 22 69 }
		$a71 = { 1C 20 21 3B 68 38 3A 27 2F 3A 29 25 68 2B 29 26 26 27 3C 68 2A 2D 68 3A 3D 26 68 21 26 68 0C 07 1B 68 25 27 2C 2D 66 }
		$a72 = { 1D 21 20 3A 69 39 3B 26 2E 3B 28 24 69 2A 28 27 27 26 3D 69 2B 2C 69 3B 3C 27 69 20 27 69 0D 06 1A 69 24 26 2D 2C 67 }
		$a73 = { 1E 22 23 39 6A 3A 38 25 2D 38 2B 27 6A 29 2B 24 24 25 3E 6A 28 2F 6A 38 3F 24 6A 23 24 6A 0E 05 19 6A 27 25 2E 2F 64 }
		$a74 = { 1F 23 22 38 6B 3B 39 24 2C 39 2A 26 6B 28 2A 25 25 24 3F 6B 29 2E 6B 39 3E 25 6B 22 25 6B 0F 04 18 6B 26 24 2F 2E 65 }
		$a75 = { 18 24 25 3F 6C 3C 3E 23 2B 3E 2D 21 6C 2F 2D 22 22 23 38 6C 2E 29 6C 3E 39 22 6C 25 22 6C 08 03 1F 6C 21 23 28 29 62 }
		$a76 = { 19 25 24 3E 6D 3D 3F 22 2A 3F 2C 20 6D 2E 2C 23 23 22 39 6D 2F 28 6D 3F 38 23 6D 24 23 6D 09 02 1E 6D 20 22 29 28 63 }
		$a77 = { 1A 26 27 3D 6E 3E 3C 21 29 3C 2F 23 6E 2D 2F 20 20 21 3A 6E 2C 2B 6E 3C 3B 20 6E 27 20 6E 0A 01 1D 6E 23 21 2A 2B 60 }
		$a78 = { 1B 27 26 3C 6F 3F 3D 20 28 3D 2E 22 6F 2C 2E 21 21 20 3B 6F 2D 2A 6F 3D 3A 21 6F 26 21 6F 0B 00 1C 6F 22 20 2B 2A 61 }
		$a79 = { 04 38 39 23 70 20 22 3F 37 22 31 3D 70 33 31 3E 3E 3F 24 70 32 35 70 22 25 3E 70 39 3E 70 14 1F 03 70 3D 3F 34 35 7E }
		$a80 = { 05 39 38 22 71 21 23 3E 36 23 30 3C 71 32 30 3F 3F 3E 25 71 33 34 71 23 24 3F 71 38 3F 71 15 1E 02 71 3C 3E 35 34 7F }
		$a81 = { 06 3A 3B 21 72 22 20 3D 35 20 33 3F 72 31 33 3C 3C 3D 26 72 30 37 72 20 27 3C 72 3B 3C 72 16 1D 01 72 3F 3D 36 37 7C }
		$a82 = { 07 3B 3A 20 73 23 21 3C 34 21 32 3E 73 30 32 3D 3D 3C 27 73 31 36 73 21 26 3D 73 3A 3D 73 17 1C 00 73 3E 3C 37 36 7D }
		$a83 = { 00 3C 3D 27 74 24 26 3B 33 26 35 39 74 37 35 3A 3A 3B 20 74 36 31 74 26 21 3A 74 3D 3A 74 10 1B 07 74 39 3B 30 31 7A }
		$a84 = { 01 3D 3C 26 75 25 27 3A 32 27 34 38 75 36 34 3B 3B 3A 21 75 37 30 75 27 20 3B 75 3C 3B 75 11 1A 06 75 38 3A 31 30 7B }
		$a85 = { 02 3E 3F 25 76 26 24 39 31 24 37 3B 76 35 37 38 38 39 22 76 34 33 76 24 23 38 76 3F 38 76 12 19 05 76 3B 39 32 33 78 }
		$a86 = { 03 3F 3E 24 77 27 25 38 30 25 36 3A 77 34 36 39 39 38 23 77 35 32 77 25 22 39 77 3E 39 77 13 18 04 77 3A 38 33 32 79 }
		$a87 = { 0C 30 31 2B 78 28 2A 37 3F 2A 39 35 78 3B 39 36 36 37 2C 78 3A 3D 78 2A 2D 36 78 31 36 78 1C 17 0B 78 35 37 3C 3D 76 }
		$a88 = { 0D 31 30 2A 79 29 2B 36 3E 2B 38 34 79 3A 38 37 37 36 2D 79 3B 3C 79 2B 2C 37 79 30 37 79 1D 16 0A 79 34 36 3D 3C 77 }
		$a89 = { 0E 32 33 29 7A 2A 28 35 3D 28 3B 37 7A 39 3B 34 34 35 2E 7A 38 3F 7A 28 2F 34 7A 33 34 7A 1E 15 09 7A 37 35 3E 3F 74 }
		$a90 = { 0F 33 32 28 7B 2B 29 34 3C 29 3A 36 7B 38 3A 35 35 34 2F 7B 39 3E 7B 29 2E 35 7B 32 35 7B 1F 14 08 7B 36 34 3F 3E 75 }
		$a91 = { 08 34 35 2F 7C 2C 2E 33 3B 2E 3D 31 7C 3F 3D 32 32 33 28 7C 3E 39 7C 2E 29 32 7C 35 32 7C 18 13 0F 7C 31 33 38 39 72 }
		$a92 = { 09 35 34 2E 7D 2D 2F 32 3A 2F 3C 30 7D 3E 3C 33 33 32 29 7D 3F 38 7D 2F 28 33 7D 34 33 7D 19 12 0E 7D 30 32 39 38 73 }
		$a93 = { 0A 36 37 2D 7E 2E 2C 31 39 2C 3F 33 7E 3D 3F 30 30 31 2A 7E 3C 3B 7E 2C 2B 30 7E 37 30 7E 1A 11 0D 7E 33 31 3A 3B 70 }
		$a94 = { 0B 37 36 2C 7F 2F 2D 30 38 2D 3E 32 7F 3C 3E 31 31 30 2B 7F 3D 3A 7F 2D 2A 31 7F 36 31 7F 1B 10 0C 7F 32 30 3B 3A 71 }
		$a95 = { 34 08 09 13 40 10 12 0F 07 12 01 0D 40 03 01 0E 0E 0F 14 40 02 05 40 12 15 0E 40 09 0E 40 24 2F 33 40 0D 0F 04 05 4E }
		$a96 = { 35 09 08 12 41 11 13 0E 06 13 00 0C 41 02 00 0F 0F 0E 15 41 03 04 41 13 14 0F 41 08 0F 41 25 2E 32 41 0C 0E 05 04 4F }
		$a97 = { 36 0A 0B 11 42 12 10 0D 05 10 03 0F 42 01 03 0C 0C 0D 16 42 00 07 42 10 17 0C 42 0B 0C 42 26 2D 31 42 0F 0D 06 07 4C }
		$a98 = { 37 0B 0A 10 43 13 11 0C 04 11 02 0E 43 00 02 0D 0D 0C 17 43 01 06 43 11 16 0D 43 0A 0D 43 27 2C 30 43 0E 0C 07 06 4D }
		$a99 = { 30 0C 0D 17 44 14 16 0B 03 16 05 09 44 07 05 0A 0A 0B 10 44 06 01 44 16 11 0A 44 0D 0A 44 20 2B 37 44 09 0B 00 01 4A }
		$a100 = { 31 0D 0C 16 45 15 17 0A 02 17 04 08 45 06 04 0B 0B 0A 11 45 07 00 45 17 10 0B 45 0C 0B 45 21 2A 36 45 08 0A 01 00 4B }
		$a101 = { 32 0E 0F 15 46 16 14 09 01 14 07 0B 46 05 07 08 08 09 12 46 04 03 46 14 13 08 46 0F 08 46 22 29 35 46 0B 09 02 03 48 }
		$a102 = { 33 0F 0E 14 47 17 15 08 00 15 06 0A 47 04 06 09 09 08 13 47 05 02 47 15 12 09 47 0E 09 47 23 28 34 47 0A 08 03 02 49 }
		$a103 = { 3C 00 01 1B 48 18 1A 07 0F 1A 09 05 48 0B 09 06 06 07 1C 48 0A 0D 48 1A 1D 06 48 01 06 48 2C 27 3B 48 05 07 0C 0D 46 }
		$a104 = { 3D 01 00 1A 49 19 1B 06 0E 1B 08 04 49 0A 08 07 07 06 1D 49 0B 0C 49 1B 1C 07 49 00 07 49 2D 26 3A 49 04 06 0D 0C 47 }
		$a105 = { 3E 02 03 19 4A 1A 18 05 0D 18 0B 07 4A 09 0B 04 04 05 1E 4A 08 0F 4A 18 1F 04 4A 03 04 4A 2E 25 39 4A 07 05 0E 0F 44 }
		$a106 = { 3F 03 02 18 4B 1B 19 04 0C 19 0A 06 4B 08 0A 05 05 04 1F 4B 09 0E 4B 19 1E 05 4B 02 05 4B 2F 24 38 4B 06 04 0F 0E 45 }
		$a107 = { 38 04 05 1F 4C 1C 1E 03 0B 1E 0D 01 4C 0F 0D 02 02 03 18 4C 0E 09 4C 1E 19 02 4C 05 02 4C 28 23 3F 4C 01 03 08 09 42 }
		$a108 = { 39 05 04 1E 4D 1D 1F 02 0A 1F 0C 00 4D 0E 0C 03 03 02 19 4D 0F 08 4D 1F 18 03 4D 04 03 4D 29 22 3E 4D 00 02 09 08 43 }
		$a109 = { 3A 06 07 1D 4E 1E 1C 01 09 1C 0F 03 4E 0D 0F 00 00 01 1A 4E 0C 0B 4E 1C 1B 00 4E 07 00 4E 2A 21 3D 4E 03 01 0A 0B 40 }
		$a110 = { 3B 07 06 1C 4F 1F 1D 00 08 1D 0E 02 4F 0C 0E 01 01 00 1B 4F 0D 0A 4F 1D 1A 01 4F 06 01 4F 2B 20 3C 4F 02 00 0B 0A 41 }
		$a111 = { 24 18 19 03 50 00 02 1F 17 02 11 1D 50 13 11 1E 1E 1F 04 50 12 15 50 02 05 1E 50 19 1E 50 34 3F 23 50 1D 1F 14 15 5E }
		$a112 = { 25 19 18 02 51 01 03 1E 16 03 10 1C 51 12 10 1F 1F 1E 05 51 13 14 51 03 04 1F 51 18 1F 51 35 3E 22 51 1C 1E 15 14 5F }
		$a113 = { 26 1A 1B 01 52 02 00 1D 15 00 13 1F 52 11 13 1C 1C 1D 06 52 10 17 52 00 07 1C 52 1B 1C 52 36 3D 21 52 1F 1D 16 17 5C }
		$a114 = { 27 1B 1A 00 53 03 01 1C 14 01 12 1E 53 10 12 1D 1D 1C 07 53 11 16 53 01 06 1D 53 1A 1D 53 37 3C 20 53 1E 1C 17 16 5D }
		$a115 = { 20 1C 1D 07 54 04 06 1B 13 06 15 19 54 17 15 1A 1A 1B 00 54 16 11 54 06 01 1A 54 1D 1A 54 30 3B 27 54 19 1B 10 11 5A }
		$a116 = { 21 1D 1C 06 55 05 07 1A 12 07 14 18 55 16 14 1B 1B 1A 01 55 17 10 55 07 00 1B 55 1C 1B 55 31 3A 26 55 18 1A 11 10 5B }
		$a117 = { 22 1E 1F 05 56 06 04 19 11 04 17 1B 56 15 17 18 18 19 02 56 14 13 56 04 03 18 56 1F 18 56 32 39 25 56 1B 19 12 13 58 }
		$a118 = { 23 1F 1E 04 57 07 05 18 10 05 16 1A 57 14 16 19 19 18 03 57 15 12 57 05 02 19 57 1E 19 57 33 38 24 57 1A 18 13 12 59 }
		$a119 = { 2C 10 11 0B 58 08 0A 17 1F 0A 19 15 58 1B 19 16 16 17 0C 58 1A 1D 58 0A 0D 16 58 11 16 58 3C 37 2B 58 15 17 1C 1D 56 }
		$a120 = { 2D 11 10 0A 59 09 0B 16 1E 0B 18 14 59 1A 18 17 17 16 0D 59 1B 1C 59 0B 0C 17 59 10 17 59 3D 36 2A 59 14 16 1D 1C 57 }
		$a121 = { 2E 12 13 09 5A 0A 08 15 1D 08 1B 17 5A 19 1B 14 14 15 0E 5A 18 1F 5A 08 0F 14 5A 13 14 5A 3E 35 29 5A 17 15 1E 1F 54 }
		$a122 = { 2F 13 12 08 5B 0B 09 14 1C 09 1A 16 5B 18 1A 15 15 14 0F 5B 19 1E 5B 09 0E 15 5B 12 15 5B 3F 34 28 5B 16 14 1F 1E 55 }
		$a123 = { 28 14 15 0F 5C 0C 0E 13 1B 0E 1D 11 5C 1F 1D 12 12 13 08 5C 1E 19 5C 0E 09 12 5C 15 12 5C 38 33 2F 5C 11 13 18 19 52 }
		$a124 = { 29 15 14 0E 5D 0D 0F 12 1A 0F 1C 10 5D 1E 1C 13 13 12 09 5D 1F 18 5D 0F 08 13 5D 14 13 5D 39 32 2E 5D 10 12 19 18 53 }
		$a125 = { 2A 16 17 0D 5E 0E 0C 11 19 0C 1F 13 5E 1D 1F 10 10 11 0A 5E 1C 1B 5E 0C 0B 10 5E 17 10 5E 3A 31 2D 5E 13 11 1A 1B 50 }
		$a126 = { 2B 17 16 0C 5F 0F 0D 10 18 0D 1E 12 5F 1C 1E 11 11 10 0B 5F 1D 1A 5F 0D 0A 11 5F 16 11 5F 3B 30 2C 5F 12 10 1B 1A 51 }
		$a127 = { D4 E8 E9 F3 A0 F0 F2 EF E7 F2 E1 ED A0 E3 E1 EE EE EF F4 A0 E2 E5 A0 F2 F5 EE A0 E9 EE A0 C4 CF D3 A0 ED EF E4 E5 AE }
		$a128 = { D5 E9 E8 F2 A1 F1 F3 EE E6 F3 E0 EC A1 E2 E0 EF EF EE F5 A1 E3 E4 A1 F3 F4 EF A1 E8 EF A1 C5 CE D2 A1 EC EE E5 E4 AF }
		$a129 = { D6 EA EB F1 A2 F2 F0 ED E5 F0 E3 EF A2 E1 E3 EC EC ED F6 A2 E0 E7 A2 F0 F7 EC A2 EB EC A2 C6 CD D1 A2 EF ED E6 E7 AC }
		$a130 = { D7 EB EA F0 A3 F3 F1 EC E4 F1 E2 EE A3 E0 E2 ED ED EC F7 A3 E1 E6 A3 F1 F6 ED A3 EA ED A3 C7 CC D0 A3 EE EC E7 E6 AD }
		$a131 = { D0 EC ED F7 A4 F4 F6 EB E3 F6 E5 E9 A4 E7 E5 EA EA EB F0 A4 E6 E1 A4 F6 F1 EA A4 ED EA A4 C0 CB D7 A4 E9 EB E0 E1 AA }
		$a132 = { D1 ED EC F6 A5 F5 F7 EA E2 F7 E4 E8 A5 E6 E4 EB EB EA F1 A5 E7 E0 A5 F7 F0 EB A5 EC EB A5 C1 CA D6 A5 E8 EA E1 E0 AB }
		$a133 = { D2 EE EF F5 A6 F6 F4 E9 E1 F4 E7 EB A6 E5 E7 E8 E8 E9 F2 A6 E4 E3 A6 F4 F3 E8 A6 EF E8 A6 C2 C9 D5 A6 EB E9 E2 E3 A8 }
		$a134 = { D3 EF EE F4 A7 F7 F5 E8 E0 F5 E6 EA A7 E4 E6 E9 E9 E8 F3 A7 E5 E2 A7 F5 F2 E9 A7 EE E9 A7 C3 C8 D4 A7 EA E8 E3 E2 A9 }
		$a135 = { DC E0 E1 FB A8 F8 FA E7 EF FA E9 E5 A8 EB E9 E6 E6 E7 FC A8 EA ED A8 FA FD E6 A8 E1 E6 A8 CC C7 DB A8 E5 E7 EC ED A6 }
		$a136 = { DD E1 E0 FA A9 F9 FB E6 EE FB E8 E4 A9 EA E8 E7 E7 E6 FD A9 EB EC A9 FB FC E7 A9 E0 E7 A9 CD C6 DA A9 E4 E6 ED EC A7 }
		$a137 = { DE E2 E3 F9 AA FA F8 E5 ED F8 EB E7 AA E9 EB E4 E4 E5 FE AA E8 EF AA F8 FF E4 AA E3 E4 AA CE C5 D9 AA E7 E5 EE EF A4 }
		$a138 = { DF E3 E2 F8 AB FB F9 E4 EC F9 EA E6 AB E8 EA E5 E5 E4 FF AB E9 EE AB F9 FE E5 AB E2 E5 AB CF C4 D8 AB E6 E4 EF EE A5 }
		$a139 = { D8 E4 E5 FF AC FC FE E3 EB FE ED E1 AC EF ED E2 E2 E3 F8 AC EE E9 AC FE F9 E2 AC E5 E2 AC C8 C3 DF AC E1 E3 E8 E9 A2 }
		$a140 = { D9 E5 E4 FE AD FD FF E2 EA FF EC E0 AD EE EC E3 E3 E2 F9 AD EF E8 AD FF F8 E3 AD E4 E3 AD C9 C2 DE AD E0 E2 E9 E8 A3 }
		$a141 = { DA E6 E7 FD AE FE FC E1 E9 FC EF E3 AE ED EF E0 E0 E1 FA AE EC EB AE FC FB E0 AE E7 E0 AE CA C1 DD AE E3 E1 EA EB A0 }
		$a142 = { DB E7 E6 FC AF FF FD E0 E8 FD EE E2 AF EC EE E1 E1 E0 FB AF ED EA AF FD FA E1 AF E6 E1 AF CB C0 DC AF E2 E0 EB EA A1 }
		$a143 = { C4 F8 F9 E3 B0 E0 E2 FF F7 E2 F1 FD B0 F3 F1 FE FE FF E4 B0 F2 F5 B0 E2 E5 FE B0 F9 FE B0 D4 DF C3 B0 FD FF F4 F5 BE }
		$a144 = { C5 F9 F8 E2 B1 E1 E3 FE F6 E3 F0 FC B1 F2 F0 FF FF FE E5 B1 F3 F4 B1 E3 E4 FF B1 F8 FF B1 D5 DE C2 B1 FC FE F5 F4 BF }
		$a145 = { C6 FA FB E1 B2 E2 E0 FD F5 E0 F3 FF B2 F1 F3 FC FC FD E6 B2 F0 F7 B2 E0 E7 FC B2 FB FC B2 D6 DD C1 B2 FF FD F6 F7 BC }
		$a146 = { C7 FB FA E0 B3 E3 E1 FC F4 E1 F2 FE B3 F0 F2 FD FD FC E7 B3 F1 F6 B3 E1 E6 FD B3 FA FD B3 D7 DC C0 B3 FE FC F7 F6 BD }
		$a147 = { C0 FC FD E7 B4 E4 E6 FB F3 E6 F5 F9 B4 F7 F5 FA FA FB E0 B4 F6 F1 B4 E6 E1 FA B4 FD FA B4 D0 DB C7 B4 F9 FB F0 F1 BA }
		$a148 = { C1 FD FC E6 B5 E5 E7 FA F2 E7 F4 F8 B5 F6 F4 FB FB FA E1 B5 F7 F0 B5 E7 E0 FB B5 FC FB B5 D1 DA C6 B5 F8 FA F1 F0 BB }
		$a149 = { C2 FE FF E5 B6 E6 E4 F9 F1 E4 F7 FB B6 F5 F7 F8 F8 F9 E2 B6 F4 F3 B6 E4 E3 F8 B6 FF F8 B6 D2 D9 C5 B6 FB F9 F2 F3 B8 }
		$a150 = { C3 FF FE E4 B7 E7 E5 F8 F0 E5 F6 FA B7 F4 F6 F9 F9 F8 E3 B7 F5 F2 B7 E5 E2 F9 B7 FE F9 B7 D3 D8 C4 B7 FA F8 F3 F2 B9 }
		$a151 = { CC F0 F1 EB B8 E8 EA F7 FF EA F9 F5 B8 FB F9 F6 F6 F7 EC B8 FA FD B8 EA ED F6 B8 F1 F6 B8 DC D7 CB B8 F5 F7 FC FD B6 }
		$a152 = { CD F1 F0 EA B9 E9 EB F6 FE EB F8 F4 B9 FA F8 F7 F7 F6 ED B9 FB FC B9 EB EC F7 B9 F0 F7 B9 DD D6 CA B9 F4 F6 FD FC B7 }
		$a153 = { CE F2 F3 E9 BA EA E8 F5 FD E8 FB F7 BA F9 FB F4 F4 F5 EE BA F8 FF BA E8 EF F4 BA F3 F4 BA DE D5 C9 BA F7 F5 FE FF B4 }
		$a154 = { CF F3 F2 E8 BB EB E9 F4 FC E9 FA F6 BB F8 FA F5 F5 F4 EF BB F9 FE BB E9 EE F5 BB F2 F5 BB DF D4 C8 BB F6 F4 FF FE B5 }
		$a155 = { C8 F4 F5 EF BC EC EE F3 FB EE FD F1 BC FF FD F2 F2 F3 E8 BC FE F9 BC EE E9 F2 BC F5 F2 BC D8 D3 CF BC F1 F3 F8 F9 B2 }
		$a156 = { C9 F5 F4 EE BD ED EF F2 FA EF FC F0 BD FE FC F3 F3 F2 E9 BD FF F8 BD EF E8 F3 BD F4 F3 BD D9 D2 CE BD F0 F2 F9 F8 B3 }
		$a157 = { CA F6 F7 ED BE EE EC F1 F9 EC FF F3 BE FD FF F0 F0 F1 EA BE FC FB BE EC EB F0 BE F7 F0 BE DA D1 CD BE F3 F1 FA FB B0 }
		$a158 = { CB F7 F6 EC BF EF ED F0 F8 ED FE F2 BF FC FE F1 F1 F0 EB BF FD FA BF ED EA F1 BF F6 F1 BF DB D0 CC BF F2 F0 FB FA B1 }
		$a159 = { F4 C8 C9 D3 80 D0 D2 CF C7 D2 C1 CD 80 C3 C1 CE CE CF D4 80 C2 C5 80 D2 D5 CE 80 C9 CE 80 E4 EF F3 80 CD CF C4 C5 8E }
		$a160 = { F5 C9 C8 D2 81 D1 D3 CE C6 D3 C0 CC 81 C2 C0 CF CF CE D5 81 C3 C4 81 D3 D4 CF 81 C8 CF 81 E5 EE F2 81 CC CE C5 C4 8F }
		$a161 = { F6 CA CB D1 82 D2 D0 CD C5 D0 C3 CF 82 C1 C3 CC CC CD D6 82 C0 C7 82 D0 D7 CC 82 CB CC 82 E6 ED F1 82 CF CD C6 C7 8C }
		$a162 = { F7 CB CA D0 83 D3 D1 CC C4 D1 C2 CE 83 C0 C2 CD CD CC D7 83 C1 C6 83 D1 D6 CD 83 CA CD 83 E7 EC F0 83 CE CC C7 C6 8D }
		$a163 = { F0 CC CD D7 84 D4 D6 CB C3 D6 C5 C9 84 C7 C5 CA CA CB D0 84 C6 C1 84 D6 D1 CA 84 CD CA 84 E0 EB F7 84 C9 CB C0 C1 8A }
		$a164 = { F1 CD CC D6 85 D5 D7 CA C2 D7 C4 C8 85 C6 C4 CB CB CA D1 85 C7 C0 85 D7 D0 CB 85 CC CB 85 E1 EA F6 85 C8 CA C1 C0 8B }
		$a165 = { F2 CE CF D5 86 D6 D4 C9 C1 D4 C7 CB 86 C5 C7 C8 C8 C9 D2 86 C4 C3 86 D4 D3 C8 86 CF C8 86 E2 E9 F5 86 CB C9 C2 C3 88 }
		$a166 = { F3 CF CE D4 87 D7 D5 C8 C0 D5 C6 CA 87 C4 C6 C9 C9 C8 D3 87 C5 C2 87 D5 D2 C9 87 CE C9 87 E3 E8 F4 87 CA C8 C3 C2 89 }
		$a167 = { FC C0 C1 DB 88 D8 DA C7 CF DA C9 C5 88 CB C9 C6 C6 C7 DC 88 CA CD 88 DA DD C6 88 C1 C6 88 EC E7 FB 88 C5 C7 CC CD 86 }
		$a168 = { FD C1 C0 DA 89 D9 DB C6 CE DB C8 C4 89 CA C8 C7 C7 C6 DD 89 CB CC 89 DB DC C7 89 C0 C7 89 ED E6 FA 89 C4 C6 CD CC 87 }
		$a169 = { FE C2 C3 D9 8A DA D8 C5 CD D8 CB C7 8A C9 CB C4 C4 C5 DE 8A C8 CF 8A D8 DF C4 8A C3 C4 8A EE E5 F9 8A C7 C5 CE CF 84 }
		$a170 = { FF C3 C2 D8 8B DB D9 C4 CC D9 CA C6 8B C8 CA C5 C5 C4 DF 8B C9 CE 8B D9 DE C5 8B C2 C5 8B EF E4 F8 8B C6 C4 CF CE 85 }
		$a171 = { F8 C4 C5 DF 8C DC DE C3 CB DE CD C1 8C CF CD C2 C2 C3 D8 8C CE C9 8C DE D9 C2 8C C5 C2 8C E8 E3 FF 8C C1 C3 C8 C9 82 }
		$a172 = { F9 C5 C4 DE 8D DD DF C2 CA DF CC C0 8D CE CC C3 C3 C2 D9 8D CF C8 8D DF D8 C3 8D C4 C3 8D E9 E2 FE 8D C0 C2 C9 C8 83 }
		$a173 = { FA C6 C7 DD 8E DE DC C1 C9 DC CF C3 8E CD CF C0 C0 C1 DA 8E CC CB 8E DC DB C0 8E C7 C0 8E EA E1 FD 8E C3 C1 CA CB 80 }
		$a174 = { FB C7 C6 DC 8F DF DD C0 C8 DD CE C2 8F CC CE C1 C1 C0 DB 8F CD CA 8F DD DA C1 8F C6 C1 8F EB E0 FC 8F C2 C0 CB CA 81 }
		$a175 = { E4 D8 D9 C3 90 C0 C2 DF D7 C2 D1 DD 90 D3 D1 DE DE DF C4 90 D2 D5 90 C2 C5 DE 90 D9 DE 90 F4 FF E3 90 DD DF D4 D5 9E }
		$a176 = { E5 D9 D8 C2 91 C1 C3 DE D6 C3 D0 DC 91 D2 D0 DF DF DE C5 91 D3 D4 91 C3 C4 DF 91 D8 DF 91 F5 FE E2 91 DC DE D5 D4 9F }
		$a177 = { E6 DA DB C1 92 C2 C0 DD D5 C0 D3 DF 92 D1 D3 DC DC DD C6 92 D0 D7 92 C0 C7 DC 92 DB DC 92 F6 FD E1 92 DF DD D6 D7 9C }
		$a178 = { E7 DB DA C0 93 C3 C1 DC D4 C1 D2 DE 93 D0 D2 DD DD DC C7 93 D1 D6 93 C1 C6 DD 93 DA DD 93 F7 FC E0 93 DE DC D7 D6 9D }
		$a179 = { E0 DC DD C7 94 C4 C6 DB D3 C6 D5 D9 94 D7 D5 DA DA DB C0 94 D6 D1 94 C6 C1 DA 94 DD DA 94 F0 FB E7 94 D9 DB D0 D1 9A }
		$a180 = { E1 DD DC C6 95 C5 C7 DA D2 C7 D4 D8 95 D6 D4 DB DB DA C1 95 D7 D0 95 C7 C0 DB 95 DC DB 95 F1 FA E6 95 D8 DA D1 D0 9B }
		$a181 = { E2 DE DF C5 96 C6 C4 D9 D1 C4 D7 DB 96 D5 D7 D8 D8 D9 C2 96 D4 D3 96 C4 C3 D8 96 DF D8 96 F2 F9 E5 96 DB D9 D2 D3 98 }
		$a182 = { E3 DF DE C4 97 C7 C5 D8 D0 C5 D6 DA 97 D4 D6 D9 D9 D8 C3 97 D5 D2 97 C5 C2 D9 97 DE D9 97 F3 F8 E4 97 DA D8 D3 D2 99 }
		$a183 = { EC D0 D1 CB 98 C8 CA D7 DF CA D9 D5 98 DB D9 D6 D6 D7 CC 98 DA DD 98 CA CD D6 98 D1 D6 98 FC F7 EB 98 D5 D7 DC DD 96 }
		$a184 = { ED D1 D0 CA 99 C9 CB D6 DE CB D8 D4 99 DA D8 D7 D7 D6 CD 99 DB DC 99 CB CC D7 99 D0 D7 99 FD F6 EA 99 D4 D6 DD DC 97 }
		$a185 = { EE D2 D3 C9 9A CA C8 D5 DD C8 DB D7 9A D9 DB D4 D4 D5 CE 9A D8 DF 9A C8 CF D4 9A D3 D4 9A FE F5 E9 9A D7 D5 DE DF 94 }
		$a186 = { EF D3 D2 C8 9B CB C9 D4 DC C9 DA D6 9B D8 DA D5 D5 D4 CF 9B D9 DE 9B C9 CE D5 9B D2 D5 9B FF F4 E8 9B D6 D4 DF DE 95 }
		$a187 = { E8 D4 D5 CF 9C CC CE D3 DB CE DD D1 9C DF DD D2 D2 D3 C8 9C DE D9 9C CE C9 D2 9C D5 D2 9C F8 F3 EF 9C D1 D3 D8 D9 92 }
		$a188 = { E9 D5 D4 CE 9D CD CF D2 DA CF DC D0 9D DE DC D3 D3 D2 C9 9D DF D8 9D CF C8 D3 9D D4 D3 9D F9 F2 EE 9D D0 D2 D9 D8 93 }
		$a189 = { EA D6 D7 CD 9E CE CC D1 D9 CC DF D3 9E DD DF D0 D0 D1 CA 9E DC DB 9E CC CB D0 9E D7 D0 9E FA F1 ED 9E D3 D1 DA DB 90 }
		$a190 = { EB D7 D6 CC 9F CF CD D0 D8 CD DE D2 9F DC DE D1 D1 D0 CB 9F DD DA 9F CD CA D1 9F D6 D1 9F FB F0 EC 9F D2 D0 DB DA 91 }
		$a191 = { 94 A8 A9 B3 E0 B0 B2 AF A7 B2 A1 AD E0 A3 A1 AE AE AF B4 E0 A2 A5 E0 B2 B5 AE E0 A9 AE E0 84 8F 93 E0 AD AF A4 A5 EE }
		$a192 = { 95 A9 A8 B2 E1 B1 B3 AE A6 B3 A0 AC E1 A2 A0 AF AF AE B5 E1 A3 A4 E1 B3 B4 AF E1 A8 AF E1 85 8E 92 E1 AC AE A5 A4 EF }
		$a193 = { 96 AA AB B1 E2 B2 B0 AD A5 B0 A3 AF E2 A1 A3 AC AC AD B6 E2 A0 A7 E2 B0 B7 AC E2 AB AC E2 86 8D 91 E2 AF AD A6 A7 EC }
		$a194 = { 97 AB AA B0 E3 B3 B1 AC A4 B1 A2 AE E3 A0 A2 AD AD AC B7 E3 A1 A6 E3 B1 B6 AD E3 AA AD E3 87 8C 90 E3 AE AC A7 A6 ED }
		$a195 = { 90 AC AD B7 E4 B4 B6 AB A3 B6 A5 A9 E4 A7 A5 AA AA AB B0 E4 A6 A1 E4 B6 B1 AA E4 AD AA E4 80 8B 97 E4 A9 AB A0 A1 EA }
		$a196 = { 91 AD AC B6 E5 B5 B7 AA A2 B7 A4 A8 E5 A6 A4 AB AB AA B1 E5 A7 A0 E5 B7 B0 AB E5 AC AB E5 81 8A 96 E5 A8 AA A1 A0 EB }
		$a197 = { 92 AE AF B5 E6 B6 B4 A9 A1 B4 A7 AB E6 A5 A7 A8 A8 A9 B2 E6 A4 A3 E6 B4 B3 A8 E6 AF A8 E6 82 89 95 E6 AB A9 A2 A3 E8 }
		$a198 = { 93 AF AE B4 E7 B7 B5 A8 A0 B5 A6 AA E7 A4 A6 A9 A9 A8 B3 E7 A5 A2 E7 B5 B2 A9 E7 AE A9 E7 83 88 94 E7 AA A8 A3 A2 E9 }
		$a199 = { 9C A0 A1 BB E8 B8 BA A7 AF BA A9 A5 E8 AB A9 A6 A6 A7 BC E8 AA AD E8 BA BD A6 E8 A1 A6 E8 8C 87 9B E8 A5 A7 AC AD E6 }
		$a200 = { 9D A1 A0 BA E9 B9 BB A6 AE BB A8 A4 E9 AA A8 A7 A7 A6 BD E9 AB AC E9 BB BC A7 E9 A0 A7 E9 8D 86 9A E9 A4 A6 AD AC E7 }
		$a201 = { 9E A2 A3 B9 EA BA B8 A5 AD B8 AB A7 EA A9 AB A4 A4 A5 BE EA A8 AF EA B8 BF A4 EA A3 A4 EA 8E 85 99 EA A7 A5 AE AF E4 }
		$a202 = { 9F A3 A2 B8 EB BB B9 A4 AC B9 AA A6 EB A8 AA A5 A5 A4 BF EB A9 AE EB B9 BE A5 EB A2 A5 EB 8F 84 98 EB A6 A4 AF AE E5 }
		$a203 = { 98 A4 A5 BF EC BC BE A3 AB BE AD A1 EC AF AD A2 A2 A3 B8 EC AE A9 EC BE B9 A2 EC A5 A2 EC 88 83 9F EC A1 A3 A8 A9 E2 }
		$a204 = { 99 A5 A4 BE ED BD BF A2 AA BF AC A0 ED AE AC A3 A3 A2 B9 ED AF A8 ED BF B8 A3 ED A4 A3 ED 89 82 9E ED A0 A2 A9 A8 E3 }
		$a205 = { 9A A6 A7 BD EE BE BC A1 A9 BC AF A3 EE AD AF A0 A0 A1 BA EE AC AB EE BC BB A0 EE A7 A0 EE 8A 81 9D EE A3 A1 AA AB E0 }
		$a206 = { 9B A7 A6 BC EF BF BD A0 A8 BD AE A2 EF AC AE A1 A1 A0 BB EF AD AA EF BD BA A1 EF A6 A1 EF 8B 80 9C EF A2 A0 AB AA E1 }
		$a207 = { 84 B8 B9 A3 F0 A0 A2 BF B7 A2 B1 BD F0 B3 B1 BE BE BF A4 F0 B2 B5 F0 A2 A5 BE F0 B9 BE F0 94 9F 83 F0 BD BF B4 B5 FE }
		$a208 = { 85 B9 B8 A2 F1 A1 A3 BE B6 A3 B0 BC F1 B2 B0 BF BF BE A5 F1 B3 B4 F1 A3 A4 BF F1 B8 BF F1 95 9E 82 F1 BC BE B5 B4 FF }
		$a209 = { 86 BA BB A1 F2 A2 A0 BD B5 A0 B3 BF F2 B1 B3 BC BC BD A6 F2 B0 B7 F2 A0 A7 BC F2 BB BC F2 96 9D 81 F2 BF BD B6 B7 FC }
		$a210 = { 87 BB BA A0 F3 A3 A1 BC B4 A1 B2 BE F3 B0 B2 BD BD BC A7 F3 B1 B6 F3 A1 A6 BD F3 BA BD F3 97 9C 80 F3 BE BC B7 B6 FD }
		$a211 = { 80 BC BD A7 F4 A4 A6 BB B3 A6 B5 B9 F4 B7 B5 BA BA BB A0 F4 B6 B1 F4 A6 A1 BA F4 BD BA F4 90 9B 87 F4 B9 BB B0 B1 FA }
		$a212 = { 81 BD BC A6 F5 A5 A7 BA B2 A7 B4 B8 F5 B6 B4 BB BB BA A1 F5 B7 B0 F5 A7 A0 BB F5 BC BB F5 91 9A 86 F5 B8 BA B1 B0 FB }
		$a213 = { 82 BE BF A5 F6 A6 A4 B9 B1 A4 B7 BB F6 B5 B7 B8 B8 B9 A2 F6 B4 B3 F6 A4 A3 B8 F6 BF B8 F6 92 99 85 F6 BB B9 B2 B3 F8 }
		$a214 = { 83 BF BE A4 F7 A7 A5 B8 B0 A5 B6 BA F7 B4 B6 B9 B9 B8 A3 F7 B5 B2 F7 A5 A2 B9 F7 BE B9 F7 93 98 84 F7 BA B8 B3 B2 F9 }
		$a215 = { 8C B0 B1 AB F8 A8 AA B7 BF AA B9 B5 F8 BB B9 B6 B6 B7 AC F8 BA BD F8 AA AD B6 F8 B1 B6 F8 9C 97 8B F8 B5 B7 BC BD F6 }
		$a216 = { 8D B1 B0 AA F9 A9 AB B6 BE AB B8 B4 F9 BA B8 B7 B7 B6 AD F9 BB BC F9 AB AC B7 F9 B0 B7 F9 9D 96 8A F9 B4 B6 BD BC F7 }
		$a217 = { 8E B2 B3 A9 FA AA A8 B5 BD A8 BB B7 FA B9 BB B4 B4 B5 AE FA B8 BF FA A8 AF B4 FA B3 B4 FA 9E 95 89 FA B7 B5 BE BF F4 }
		$a218 = { 8F B3 B2 A8 FB AB A9 B4 BC A9 BA B6 FB B8 BA B5 B5 B4 AF FB B9 BE FB A9 AE B5 FB B2 B5 FB 9F 94 88 FB B6 B4 BF BE F5 }
		$a219 = { 88 B4 B5 AF FC AC AE B3 BB AE BD B1 FC BF BD B2 B2 B3 A8 FC BE B9 FC AE A9 B2 FC B5 B2 FC 98 93 8F FC B1 B3 B8 B9 F2 }
		$a220 = { 89 B5 B4 AE FD AD AF B2 BA AF BC B0 FD BE BC B3 B3 B2 A9 FD BF B8 FD AF A8 B3 FD B4 B3 FD 99 92 8E FD B0 B2 B9 B8 F3 }
		$a221 = { 8A B6 B7 AD FE AE AC B1 B9 AC BF B3 FE BD BF B0 B0 B1 AA FE BC BB FE AC AB B0 FE B7 B0 FE 9A 91 8D FE B3 B1 BA BB F0 }
		$a222 = { 8B B7 B6 AC FF AF AD B0 B8 AD BE B2 FF BC BE B1 B1 B0 AB FF BD BA FF AD AA B1 FF B6 B1 FF 9B 90 8C FF B2 B0 BB BA F1 }
		$a223 = { B4 88 89 93 C0 90 92 8F 87 92 81 8D C0 83 81 8E 8E 8F 94 C0 82 85 C0 92 95 8E C0 89 8E C0 A4 AF B3 C0 8D 8F 84 85 CE }
		$a224 = { B5 89 88 92 C1 91 93 8E 86 93 80 8C C1 82 80 8F 8F 8E 95 C1 83 84 C1 93 94 8F C1 88 8F C1 A5 AE B2 C1 8C 8E 85 84 CF }
		$a225 = { B6 8A 8B 91 C2 92 90 8D 85 90 83 8F C2 81 83 8C 8C 8D 96 C2 80 87 C2 90 97 8C C2 8B 8C C2 A6 AD B1 C2 8F 8D 86 87 CC }
		$a226 = { B7 8B 8A 90 C3 93 91 8C 84 91 82 8E C3 80 82 8D 8D 8C 97 C3 81 86 C3 91 96 8D C3 8A 8D C3 A7 AC B0 C3 8E 8C 87 86 CD }
		$a227 = { B0 8C 8D 97 C4 94 96 8B 83 96 85 89 C4 87 85 8A 8A 8B 90 C4 86 81 C4 96 91 8A C4 8D 8A C4 A0 AB B7 C4 89 8B 80 81 CA }
		$a228 = { B1 8D 8C 96 C5 95 97 8A 82 97 84 88 C5 86 84 8B 8B 8A 91 C5 87 80 C5 97 90 8B C5 8C 8B C5 A1 AA B6 C5 88 8A 81 80 CB }
		$a229 = { B2 8E 8F 95 C6 96 94 89 81 94 87 8B C6 85 87 88 88 89 92 C6 84 83 C6 94 93 88 C6 8F 88 C6 A2 A9 B5 C6 8B 89 82 83 C8 }
		$a230 = { B3 8F 8E 94 C7 97 95 88 80 95 86 8A C7 84 86 89 89 88 93 C7 85 82 C7 95 92 89 C7 8E 89 C7 A3 A8 B4 C7 8A 88 83 82 C9 }
		$a231 = { BC 80 81 9B C8 98 9A 87 8F 9A 89 85 C8 8B 89 86 86 87 9C C8 8A 8D C8 9A 9D 86 C8 81 86 C8 AC A7 BB C8 85 87 8C 8D C6 }
		$a232 = { BD 81 80 9A C9 99 9B 86 8E 9B 88 84 C9 8A 88 87 87 86 9D C9 8B 8C C9 9B 9C 87 C9 80 87 C9 AD A6 BA C9 84 86 8D 8C C7 }
		$a233 = { BE 82 83 99 CA 9A 98 85 8D 98 8B 87 CA 89 8B 84 84 85 9E CA 88 8F CA 98 9F 84 CA 83 84 CA AE A5 B9 CA 87 85 8E 8F C4 }
		$a234 = { BF 83 82 98 CB 9B 99 84 8C 99 8A 86 CB 88 8A 85 85 84 9F CB 89 8E CB 99 9E 85 CB 82 85 CB AF A4 B8 CB 86 84 8F 8E C5 }
		$a235 = { B8 84 85 9F CC 9C 9E 83 8B 9E 8D 81 CC 8F 8D 82 82 83 98 CC 8E 89 CC 9E 99 82 CC 85 82 CC A8 A3 BF CC 81 83 88 89 C2 }
		$a236 = { B9 85 84 9E CD 9D 9F 82 8A 9F 8C 80 CD 8E 8C 83 83 82 99 CD 8F 88 CD 9F 98 83 CD 84 83 CD A9 A2 BE CD 80 82 89 88 C3 }
		$a237 = { BA 86 87 9D CE 9E 9C 81 89 9C 8F 83 CE 8D 8F 80 80 81 9A CE 8C 8B CE 9C 9B 80 CE 87 80 CE AA A1 BD CE 83 81 8A 8B C0 }
		$a238 = { BB 87 86 9C CF 9F 9D 80 88 9D 8E 82 CF 8C 8E 81 81 80 9B CF 8D 8A CF 9D 9A 81 CF 86 81 CF AB A0 BC CF 82 80 8B 8A C1 }
		$a239 = { A4 98 99 83 D0 80 82 9F 97 82 91 9D D0 93 91 9E 9E 9F 84 D0 92 95 D0 82 85 9E D0 99 9E D0 B4 BF A3 D0 9D 9F 94 95 DE }
		$a240 = { A5 99 98 82 D1 81 83 9E 96 83 90 9C D1 92 90 9F 9F 9E 85 D1 93 94 D1 83 84 9F D1 98 9F D1 B5 BE A2 D1 9C 9E 95 94 DF }
		$a241 = { A6 9A 9B 81 D2 82 80 9D 95 80 93 9F D2 91 93 9C 9C 9D 86 D2 90 97 D2 80 87 9C D2 9B 9C D2 B6 BD A1 D2 9F 9D 96 97 DC }
		$a242 = { A7 9B 9A 80 D3 83 81 9C 94 81 92 9E D3 90 92 9D 9D 9C 87 D3 91 96 D3 81 86 9D D3 9A 9D D3 B7 BC A0 D3 9E 9C 97 96 DD }
		$a243 = { A0 9C 9D 87 D4 84 86 9B 93 86 95 99 D4 97 95 9A 9A 9B 80 D4 96 91 D4 86 81 9A D4 9D 9A D4 B0 BB A7 D4 99 9B 90 91 DA }
		$a244 = { A1 9D 9C 86 D5 85 87 9A 92 87 94 98 D5 96 94 9B 9B 9A 81 D5 97 90 D5 87 80 9B D5 9C 9B D5 B1 BA A6 D5 98 9A 91 90 DB }
		$a245 = { A2 9E 9F 85 D6 86 84 99 91 84 97 9B D6 95 97 98 98 99 82 D6 94 93 D6 84 83 98 D6 9F 98 D6 B2 B9 A5 D6 9B 99 92 93 D8 }
		$a246 = { A3 9F 9E 84 D7 87 85 98 90 85 96 9A D7 94 96 99 99 98 83 D7 95 92 D7 85 82 99 D7 9E 99 D7 B3 B8 A4 D7 9A 98 93 92 D9 }
		$a247 = { AC 90 91 8B D8 88 8A 97 9F 8A 99 95 D8 9B 99 96 96 97 8C D8 9A 9D D8 8A 8D 96 D8 91 96 D8 BC B7 AB D8 95 97 9C 9D D6 }
		$a248 = { AD 91 90 8A D9 89 8B 96 9E 8B 98 94 D9 9A 98 97 97 96 8D D9 9B 9C D9 8B 8C 97 D9 90 97 D9 BD B6 AA D9 94 96 9D 9C D7 }
		$a249 = { AE 92 93 89 DA 8A 88 95 9D 88 9B 97 DA 99 9B 94 94 95 8E DA 98 9F DA 88 8F 94 DA 93 94 DA BE B5 A9 DA 97 95 9E 9F D4 }
		$a250 = { AF 93 92 88 DB 8B 89 94 9C 89 9A 96 DB 98 9A 95 95 94 8F DB 99 9E DB 89 8E 95 DB 92 95 DB BF B4 A8 DB 96 94 9F 9E D5 }
		$a251 = { A8 94 95 8F DC 8C 8E 93 9B 8E 9D 91 DC 9F 9D 92 92 93 88 DC 9E 99 DC 8E 89 92 DC 95 92 DC B8 B3 AF DC 91 93 98 99 D2 }
		$a252 = { A9 95 94 8E DD 8D 8F 92 9A 8F 9C 90 DD 9E 9C 93 93 92 89 DD 9F 98 DD 8F 88 93 DD 94 93 DD B9 B2 AE DD 90 92 99 98 D3 }
		$a253 = { AA 96 97 8D DE 8E 8C 91 99 8C 9F 93 DE 9D 9F 90 90 91 8A DE 9C 9B DE 8C 8B 90 DE 97 90 DE BA B1 AD DE 93 91 9A 9B D0 }
		
	condition:
		any of them
}

rule Base64d_PE
{
	meta:
		description = "Contains a base64-encoded executable"
		author = "Florian Roth"
		date = "2017-04-21"
		
	strings:
		$s0 = "TVqQAAIAAAAEAA8A//8AALgAAAA" wide ascii
		$s1 = "TVqQAAMAAAAEAAAA//8AALgAAAA" wide ascii
		
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
        $a1 = "virus" nocase ascii wide fullword
        $a2 = "hack" nocase ascii wide fullword
        $a3 = "exploit" nocase ascii wide
        $a4 = "cmd.exe" nocase ascii wide
        $a5 = "CWSandbox" nocase wide ascii // Found in some Zeus/Citadel samples
        $a6 = "System32\\drivers\\etc\\hosts" nocase wide ascii
    condition:
        any of them
}

rule BITS_CLSID
{
    meta:
        description = "References the BITS service."
        author = "Ivan Kwiatkowski (@JusticeRage)"
		show_strings = "false"
        // The BITS service seems to be used heavily by EquationGroup.
    strings:
        $uuid_background_copy_manager_1_5 =     { 1F 77 87 F0 4F D7 1A 4C BB 8A E1 6A CA 91 24 EA }
        $uuid_background_copy_manager_2_0 =     { 12 AD 18 6D E3 BD 93 43 B3 11 09 9C 34 6E 6D F9 }
        $uuid_background_copy_manager_2_5 =     { D6 98 CA 03 5D FF B8 49 AB C6 03 DD 84 12 70 20 }
        $uuid_background_copy_manager_3_0 =     { A7 DE 9C 65 9E 48 D9 11 A9 CD 00 0D 56 96 52 51 }
        $uuid_background_copy_manager_4_0 =     { 6B F5 6D BB CE CA DC 11 99 92 00 19 B9 3A 3A 84 }
        $uuid_background_copy_manager_5_0 =     { 4C A3 CC 1E 8A E8 E3 44 8D 6A 89 21 BD E9 E4 52 }
        $uuid_background_copy_manager =         { 4B D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97 }
        $uuid_ibackground_copy_manager =        { 0D 4C E3 5C C9 0D 1F 4C 89 7C DA A1 B7 8C EE 7C }
        $uuid_background_copy_qmanager =        { 69 AD 4A EE 51 BE 43 9B A9 2C 86 AE 49 0E 8B 30 }
        $uuid_ibits_peer_cache_administration = { AD DE 9C 65 9E 48 D9 11 A9 CD 00 0D 56 96 52 51 }
        $uuid_background_copy_callback =        { C7 99 EA 97 86 01 D4 4A 8D F9 C5 B4 E0 ED 6B 22 }
    condition:
        any of them
}

rule Mimikatz
{
	meta:
		description = "Contains code from Mimikatz."
		author = "Ivan Kwiatkowski (@JusticeRage)"
		show_strings = "false"
	strings:
		$x64_W2K3_SecData =    { 48 8d 6e 30 48 8d 0d }
		$x64_W2K8_SecData =    { 48 8d 94 24 b0 00 00 00 48 8d 0d }
		$x64_W2K12_SecData =   { 4c 8d 85 30 01 00 00 48 8d 15 }
		$x64_W2K12R2_SecData = { 0f b6 4c 24 30 85 c0 0f 45 cf 8a c1 }
		$x64_WI52_SysCred =    { b9 14 00 00 00 f3 aa 48 8d 3d }
		$x64_WI60_SysCred =    { 48 8b ca f3 aa 48 8d 3d }
		$x64_WI61_SysCred =    { 8b ca f3 aa 48 8d 3d }
		$x86_W2K3_SecData =    { 53 56 8d 45 98 50 b9 }
		$x86_W2K8_SecData =    { 8b 45 14 83 c0 18 50 b9 }
		$x86_WI51_SysCred =    { 00 ab 33 c0 bf }
		$x86_WI52_SysCred =    { 59 33 d2 88 10 40 49 75 }
		$x86_WI60_SysCred =    { 6a 14 59 b8 }
		$x86_WI62_SysCred =    { 6a 14 5a 8b f2 b9 }
		$x86_WI63_SysCred =    { 6a 14 59 8b d1 b8 }
	condition:
		all of ($x64_*) or all of ($x86_*)
}

rule Mimikatz_2
{
	meta:
		description = "Contains strings from Mimikatz"
		author = "Ivan Kwiatkowski (@JusticeRage)"
	strings:
		$primary = "Primary" fullword
		$credentialkeys = "CredentialKeys" fullword
		$bcrypt1 = "BCryptCloseAlgorithmProvider" fullword
		$bcrypt2 = "BCryptDestroyKey" fullword
		$bcrypt3 = "BCryptDecrypt" fullword
		$bcrypt4 = "BCryptEncrypt" fullword
		$bcrypt5 = "BCryptGenerateSymmetricKey" fullword
		$bcrypt6 = "BCryptGetProperty" fullword
		$bcrypt7 = "BCryptSetProperty" fullword
		$bcrypt8 = "BCryptOpenAlgorithmProvider" fullword
	condition:
		$primary and $credentialkeys and 5 of ($bcrypt*)
}

rule MiningPool
{
    meta:
        description = "Contains references to mining pools"
        author = "Ivan Kwiatkowski (@JusticeRage), based on an idea from @__Emilien__"
    strings:
        $stratum = /stratum\+tcp:\/\/[A-Za-z0-9-.:]*/
    condition:
        $stratum
}
