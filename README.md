# AOL7-Retro-Server
A Python-based server emulator for the vintage AOL 7.0 Client (2001), enabling the proprietary P3 Tunnel Protocol and defeating the internal security mechanisms.

📖 About The Project
This project aims to resurrect the AOL 7.0 Client by reverse-engineering the server-side infrastructure. Unlike standard AIM clients that communicate directly via OSCAR, the main AOL client uses a heavily encrypted, proprietary encapsulation protocol known as P3.

For years, the AOL 7.0 client stuck at the "Handshake" or "Verifying Password" stage because the specific P3 mechanism and the client's internal RSA/RC4 security engine (sec.cct) were completely undocumented. This project successfully implements the P3 Handshake, In-Band Multiplexing, and actively defeats the client-side cryptography token verification, allowing the client to fully transition into the ONLINE state.

This is strictly for educational and preservation purposes.

🚀 Current Status (v0.7.0 "Security Defeated")
We have successfully reverse-engineered the entire connection and authentication sequence. The server architecture now handles:

✅ Two-Server Architecture: Seamless handoff between Login-Server (Port 5190) and BOS-Server (Port 5194).

✅ In-Band Proxy Tunneling: Perfectly handles the transparent proxying of Channel 0x11 handshakes over the existing P3 socket.

✅ Sequence Number Patching: On-the-fly LCG sequence rewriting to prevent client-side packet drops.

✅ Session-Init & Service Lists: Successfully responds to TYPE=0xA0 requests, initializing the client's internal service structures.

🔥 Security Verification Bypass: Utillizes a dynamic DLL injector (inject.py / axxxxc.xxx) to patch the client's memory (FUN_6xxxxxxx) on the fly, forcing a return 1 (XX 0X 00 00 00 XX) and completely bypassing the RSA/RC4 token integrity checks.

🛠 Technical Insights
The AOL 7.0 client is heavily state-dependent and utilizes an asynchronous security validation mechanism that is notoriously difficult to emulate.

1. In-Band Handoff (Channel 0x11)
When transitioning from the Auth phase to the BOS (Basic OSCAR Service) phase, the client doesn't open a new TCP socket. Instead, it multiplexes a new connection inside the existing tunnel via Channel 0x11. Our proxy intercepts this in-band challenge, extracts the new dynamic session seed, and passes it to the BOS server to keep the RC4 stream perfectly synchronized.

2. Defeating sec.cct (The Token Bypass)
The client requires a cryptographic token to proceed. Instead of cracking the 20-year-old private keys, we developed a C-based stub (axxxxc.xxx) that is injected into waol.exe. It waits for the security engine to load, locates the verification routine, and writes a hardcoded return true ASM patch directly into the RAM. The server then feeds the client a static fallback token, which the client now unconditionally accepts.

💻 Getting Started
Prerequisites
Python 3.x

GCC (MinGW) for compiling the C-stub (already compiled as aolsec.cct)

AOL 7.0 Client (English or German version) installed on a VM or retro machine.

🗺 Roadmap
[x] Protocol Analysis & CRC reversing

[x] Stable P3 Handshake & Identity Mirroring

[x] State Machine Advance (Auth -> Online)

[x] Implement In-Band BOS Handoff (Channel 0x11)

[x] Defeat Client-Side Security & Token Verification (sec.cct)

[x] Implement Discovery Response & Service List Negotiation

[ ] Implement Full CSL (Common Services Layer) handling

[ ] Parse standard OSCAR SNACs wrapped in P3

[ ] Basic Registration FDO (Form Definition Object)

[ ] Display the Welcome Screen & Buddy List

🤝 Contributing
Contributions are welcome! If you have knowledge of the P3 protocol, FDO bytecode, or OSCAR SNACs wrapped in P3, please open an issue or submit a pull request.

🏆 Credits & Acknowledgments
Community: Thanks to the reverse engineering community for documenting the base OSCAR protocol.

⚠️ Disclaimer
This project is an independent effort and is not affiliated with, endorsed by, or connected to AOL, Verizon, Yahoo, or their subsidiaries. All trademarks belong to their respective owners. This software is provided "as is" for archival and educational purposes only.
