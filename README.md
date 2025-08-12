[Pawan Shivarkar — Staff Offensive Security Researcher @ NVIDIA](https://www.nvidia.com)

- 👋 Hi, I’m [**Pawan Shivarkar**](https://github.com/pawan-shivarkar),] A Security Researcher interested in Vulnerability Research, Malware, Fuzzing, and Low-Level Security.
- Currently working as a [Staff Offensive Security Researcher @ NVIDIA](https://www.nvidia.com), focusing on Embedded Firmware and critical System Software across HPC, AI/cloud, autonomous and IoT platforms performing offensive research, vulnerability discovery, and exploitation across diverse HW/SW targets.
-    Previously, I was [Manager, Security Research @ Qualys](https://www.qualys.com), Lead Vulnerabiity Research on OSS, Linux, and system software under the Threat Research Unit.  
-    I’ve also held roles at [Microsoft](https://www.microsoft.com/en-us/msrc) (MSRC), [FireEye](https://www.fireeye.com) (FLARE-OTF), and [Symantec](https://www.broadcom.com/company/newsroom/press-releases?filtr=Symantec) (STAR Team), specializing in vulnerability and malware research.

Some of my work: (_This is currated list of my findings Individual + Collaborative work.._)
-------------------------------------------------------------------------------------------------------

🚨 **This is just a list of High‑Impact Vulns _[full list of CVE's available here_](https://github.com/pawan-shivarkar/List-of-CVE-s-)_** 🚨

- 🌟**0‑Days**
  - [CVE‑2025‑32709](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2025-32709) — UAF in Windows WinSock Ancillary Function Driver leading to EoP(Windows AFD.sys Zero-Day), [(Individual)](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2025-32709)
  - [CVE-2024-4671](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-4671) — Chrome Visuals UAF leading to sandbox escape. (0-day) [(Individual)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-4671)
  - [CVE-2022-1096](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1096) — Type confusion vuln in V8 JavaScript engine of Google Chrome(0day), [(Individual)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1096)
  - [CVE-2021-30883](https://support.apple.com/en-in/103159) — Apple's IOMobileFrameBuffer Memory Corruption leading Kernel RCE (0day), [(Individual)](https://support.apple.com/en-in/103159)
  - [CVE-2021-1647](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1647) – Windows Defender mpengine heap overflow via crafted PE file. [(in-wild 0day)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1647) (MSRC)
  - [CVE-2020-17087](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-17087?utm_source=SECDEV+Audience++PRIME+-+APRIL+2020&utm_campaign=4c30f3205c-DRF-19-October-2020_COPY_01&utm_medium=email&utm_term=0_6e92156d31-4c30f3205c-&mc_cid=4c30f3205c&mc_eid=%5BUNIQID%5D) — Windows Kernel EOP vulnerability in CNG.sys, [(Individual)](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-17087?utm_source=SECDEV+Audience++PRIME+-+APRIL+2020&utm_campaign=4c30f3205c-DRF-19-October-2020_COPY_01&utm_medium=email&utm_term=0_6e92156d31-4c30f3205c-&mc_cid=4c30f3205c&mc_eid=%5BUNIQID%5D)
  - [CVE-2021-30890](https://support.apple.com/en-bn/103166) — WebKit uXSS via Logic Bug on macOS, [(Individual)](https://support.apple.com/en-bn/103166)
  - [CVE‑2022‑22675](https://support.apple.com/en-us/102999) — AppleAVD out-of-bounds write, kernel code execution, [(Individual)](https://support.apple.com/en-us/102999)
  - [CVE‑2020‑0673](https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0673) – IE Scripting Engine Memory Corruption RCE via scripting engine object handling. (in-wild 0day) (MSRC)
 
- 🚨 **Critical Impact**
  - [CVE‑2024‑6387](https://www.qualys.com/regresshion-cve-2024-6387/) — OpenSSH server (sshd) Signal-handler race regression [(“regreSSHion”)](https://www.qualys.com/regresshion-cve-2024-6387/) enabling remote, unauth RCE as root on glibc-based Linux systems,(Qualys TRU)
  - [CVE‑2020‑0796](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796)  – SMBv3 compression integer‑overflow wormable RCE [(SMBGhost)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796) (MSRC) (Involved in mitigation)
  - [CVE‑2024‑43447](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43447) – SMBv3 server double‑free RCE on Windows Server 2022, [(Individual)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43447)
  - [CVE‑2023‑23374](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23374) – Microsoft Edge (Chromium/Android) RCE,[(Individual)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23374) (MSRC)
  - CVE‑2024‑3411  – Weak IPMI session auth randomness in BMCs allows remote hijack and full server compromise, Affects multiple OEM BMCs.
  - CVE‑2023‑28863 – AMI MegaRAC BMC Predictable IPMI session IDs enables remote unauth IPMI sessions hijack and full server control.
  - CVE‑2020‑0594  – Intel AMT/ISM firmware OOB read in IPv6 subsystem of allows unauthenticated remote escalation via network access
  - CVE‑2020‑0595  – Intel AMT/ISM firmware UAF in IPv6 handler of enabling unauthenticated remote privilege escalation
  - [CVE-2019-2294](https://docs.qualcomm.com/product/publicresources/securitybulletin/august-2019-bulletin.html)  — Qualcomm Audio DSP heap corruption via hardcoded heap guard magic in memory management, [(Individual)](https://docs.qualcomm.com/product/publicresources/securitybulletin/august-2019-bulletin.html)
  - [CVE‑2022‑24537](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-24537) – Hyper‑V guest‑to‑host RCE via improper sync race in driver, (MSRC)
  - [CVE‑2021‑34450](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-34450) – Hyper‑V guest‑to‑host RCE via network Hyper‑V sync bug (MSRC) [(Individual)](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-34450)
  - [CVE-2025-30452](https://support.apple.com/en-us/122373) — Input validation vulnerability in sandbox component of macOS, [(Individual)](https://support.apple.com/en-us/122373)
  - [CVE-2019-8285](https://securityvulnerability.io/vulnerability/CVE-2019-8285) — Kaspersky Antivirus Engine Heap BOF Vulnerability, [(Individual)](https://securityvulnerability.io/vulnerability/CVE-2019-8285)
  - [CVE-2017-13843](https://support.apple.com/en-us/103804) — macOS Kernel Memory Corruption Leading to Kernel Priv Esc(Kernel RCE), [(Individual)](https://support.apple.com/en-us/103804)
  - [CVE-2016-4726](https://support.apple.com/en-mk/103800)— Apple's IOAcceleratorFamily memory corruption leading to kernel RCE. [(Individual)](https://support.apple.com/en-mk/103800)
  - [CVE-2014-0198](https://bugzilla.redhat.com/show_bug.cgi?id=1093837) — OpenSSL Recursion flaw in DTLS handshake packet handling leading to remote DoS, [(Individual)](https://bugzilla.redhat.com/show_bug.cgi?id=1093837)
  - CVE-2012-1721  — Oracle Java SE Rhino script engine flaw in ≤7u4/6u32, remote unauth code exec via crafted Java applet/web start app.
  - CVE‑2016‑0002  — IE 8–11 RCE in VBScript/JScript engines via memory corruption from malformed objects.
  - No CVE (RCE)   – Stack BOF in Symantec AV engine via crafted RAR archive triggers RCE during file scan.
  - No CVE(Chain Exploit): Chrome exploit: WebAssembly type confusion + V8 OOB read + sandbox escape, (Individual)
 
- ⚡ **High‑Impact (_This is a curated list that I feel deserves a mention regardless of CVSS score_)**
  - No CVE (Bypass) — Three bypasses of Ubuntu's unprivileged user namespace restrictions, (Qualys TRU)
  - No CVE (Memory Corruption): Nontransitive comparison functions leading to OOB read & write in glibc's qsort(), (Qualys TRU)
  - No CVE (Logic Error): Intel 4th–7th Gen Core platform FW auth bypass and incorrect TPM measurements, enabling LPE, [(Individual)]()
  - CVE-2019-8544 — WebKit(Safari, WebKitGTK, iTunes) Mem Corruption via crafted Web Content leading arbitrary code exec, (Individual)
  - CVE-2025-6018 — Chained LPE via PAM misconfiguration in SUSE Linux (Leap 15 & SLE 15) and openSUSE distros (Qualys TRU)
  - [CVE‑2023‑4911](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so) — Looney Tunables: glibc ld.so LPE, (Qualys TRU)
  - [CVE‑2023‑38408](https://blog.qualys.com/vulnerabilities-threat-research/2023/07/19/cve-2023-38408-remote-code-execution-in-opensshs-forwarded-ssh-agent) — OpenSSH Forwarded ssh-agent RCE, (Qualys TRU)
  - [CVE‑2025‑26465](https://blog.qualys.com/vulnerabilities-threat-research/2025/02/18/qualys-tru-discovers-two-vulnerabilities-in-openssh-cve-2025-26465-cve-2025-26466) — OpenSSH client MitM attack against mishandled VerifyHostKeyDNS-enabled clients. (Qualys TRU)
  - [CVE‑2017‑5130](https://ubuntu.com/security/CVE-2017-5130) — libxml2 Integer overflow in xmlmemory.c leading to heap corruption via crafted XML, [(Individual)](https://ubuntu.com/security/CVE-2017-5130)
  - CVE-2022-38023 — Netlogon RPC EoP due to weak RC4-HMAC encryption on Windows (Server 2008–2022 & clients in AD) (MSRC)
  - CVE-2017-13843 — macOS Kernel Memory Corruption Leading to Kernel Priv Esc(Kernel RCE), (Individual)
  - CVE‑2017‑15118 — Stack-based BOF in QEMU’s NBD server implementation (export-name length mishandling), (Individual)
  - CVE‑2017‑2620  — Out‑of‑bounds access vuln in QEMU’s Cirrus CLGD 54xx VGA emulator, (Individual)
  - CVE-2016-7663 — Apples CoreFoundation String Parsing Memory Corruption, (Individual)


Tracked Multiple in-the-wild 0-days while working at Fireeye and Microsoft, botnets and malware campaigns, APT research (e.g. Strider, Sowbug, Regin, Duqu 2.0, LoJax EFI Bootkit  Mebroot MBR rootkit, Zacinlo, APT 41, Turla (Uroburos)).

*Note: These are some of my vulns I discovered through my independent research, team collaborations, and Individual work at Qualys, MSRC, and the Oracle kernel team.

- 📫 How to reach me - (pawan@tutanota.de) ...
                        (pvn.1989@gmail.com)
<!---
pawan-shivarkar/pawan-shivarkar is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->
