# AOL7-Retro-Server
A Python-based server emulator for the vintage AOL 7.0 Client (2001), enabling the proprietary P3 Tunnel Protocol.

📖 About The Project
This project aims to resurrect the AOL 7.0 Client by reverse-engineering the server-side infrastructure. Unlike standard AIM clients that communicate directly via OSCAR, the main AOL client uses a proprietary encapsulation protocol known as P3.

For years, the AOL 7.0 client stuck at the "Handshake" or "Verifying Password" stage because the specific P3 handshake mechanism was undocumented. This project successfully implements the P3 Handshake, Identity Mirroring, and State Machine transitions required to get the client online.

This is strictly for educational and preservation purposes.

🚀 Current Status (v0.44 "True Echo")
We have successfully reverse-engineered the initial connection sequence. The server currently handles:

✅ TCP Connection Handling: Listens on Port 5190.

✅ P3 Protocol Encapsulation: Handles 0x5A framed packets with CRC checks.

✅ Seed Negotiation: Calculates correct session seeds for packet encryption/verification.

✅ Identity Mirroring (True Echo): Correctly reflects the client's Identity Structure back to pass the internal memcmp integrity check.

✅ State Advancement: Transitions the client from AUTH state to ONLINE state using Opcode 0x0003.

🚧 Discovery & Services: Currently implementing the CSL (Common Services Layer) request handling.

🚧 Registration/Sign-On: Initial FDO (Form Definition Object) handling is in progress.

🛠 Technical Insights
The AOL 7.0 client is heavily state-dependent. The breakthrough in this project was understanding that the client requires a "True Echo" of its Identity Packet.

The P3 Handshake Flow
Handshake: Server and Client exchange seeds.

Identity Request: Client sends a struct containing version info and random data.

Identity Mirror: Server must return this payload byte-perfectly. Any modification (even updating timestamps) causes the client's internal integrity check to fail, triggering a retry loop.

State Advance: Server sends Opcode 0x0003 with specific flags (ONLINE_READY) and Expected_Length = 0.

Discovery: Client wakes up and requests available services.

💻 Getting Started
Prerequisites
Python 3.x

AOL 7.0 Client (English or German version) installed on a VM or retro machine.

Start the Server:

Bash
python aol_server_0.2.148.py
Start AOL 7.0: Click on "New Member" or "Sign On". Watch the console for the P3 Handshake!

🗺 Roadmap
[x] Protocol Analysis & CRC reversing

[x] Stable Handshake (Identity Mirror Fix)

[x] State Machine Advance (Auth -> Online)

[ ] Implement Discovery Response (Service List)

[ ] Implement CSL (Common Services Layer)

[ ] Basic Registration FDO (Form Definition Object)

[ ] Buddy List & Chat functionality

🤝 Contributing
Contributions are welcome! If you have knowledge of the P3 protocol, FDO bytecode, or OSCAR SNACs wrapped in P3, please open an issue or submit a pull request.

🏆 Credits & Acknowledgments

Community: Thanks to the reverse engineering community for documenting the base OSCAR protocol.

⚠️ Disclaimer
This project is an independent effort and is not affiliated with, endorsed by, or connected to AOL, Verizon, Yahoo, or their subsidiaries. All trademarks belong to their respective owners. This software is provided "as is" for archival and educational purposes only.
