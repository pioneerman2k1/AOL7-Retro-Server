# AOL 7.0 Retro Server

A Python-based server emulator for the vintage AOL 7.0 Client (2001), reviving the proprietary P3 protocol and driving the old client all the way through login, the security handshake, and into a live online session — entirely against local emulation servers.

---

## 📖 About The Project

This project resurrects the AOL 7.0 Client by reverse-engineering the server-side infrastructure. Unlike standard AIM clients that speak OSCAR directly, the full AOL client wraps everything in a heavily encrypted, proprietary protocol called P3.

For years the AOL 7.0 client got stuck at the "Handshake" / "Verifying Password" stage, because the P3 mechanism and the client's internal security engine were undocumented. This project now drives the client cleanly through the entire login sequence and into a fully stable online session — handshake, session setup, the completed security challenge, buddy-list/online-status, and the post-login data stream — without crashes or error dialogs.

*Strictly for educational and preservation purposes.*

---

## 🚀 Current Status — v1.0.0 "The Completion Update"

The client now completes a full, error-free login, establishes a permanent secure connection, and fully renders the classic interface against the emulator:

* **✅ Two-Server Architecture** – Seamless handoff between the Login server and the BOS server.
* **✅ In-Band Proxy Tunneling** – Transparent proxying of the secondary handshake over the existing connection.
* **✅ Deep Security Layer Mastered** – The security challenge is not just bypassed, but cryptographically completed. The client's internal security engine is fully satisfied.
* **✅ 🎉 Infinite Session Stability** – The connection stays alive indefinitely. The historical 40-second timeout/disconnect loop has been completely defeated.
* **✅ 🖼️ Live Interface & Welcome Screen** – The server now successfully delivers and renders the iconic "Welcome" screen and main navigation windows directly inside the client.
* **✅ 👥 Functional Buddy List & Door Icons** – The Buddy List is fully operational. Buddies are correctly sorted into online/offline states, and the legendary door icons open and close in real-time.
* **✅ Clean Run** – No crashes, no freezes, and no generic AOL error pop-ups during the entire session.

In short: we went from *"the client refuses every connection"* to a fully working, permanently stable retro-session with a functioning user interface.

---

## 🧩 The Big Breakthroughs

* **The Crypto Synchronization:** By correcting a microscopic timing and data alignment issue in the handshake transcript, the client's strict security layer now fully accepts the server's encryption keys, allowing for an uninterrupted, permanent connection.
* **Decoding the Interface Matrix:** We deciphered how the client builds its windows dynamically from server data. Instead of hardcoded windows, the server now actively feeds the client the structure it needs to display the Welcome Screen and Buddy List.
* **The Formatting Standard:** Discovered and resolved a subtle difference in how the client expects its data packets to be structured. Aligning the server exactly with the client's ancient parsing logic stopped the client from silently dropping server responses.

---

## 🗺️ Roadmap

- [x] Stable P3 Handshake & Identity Mirroring
- [x] State Machine Advance (Auth → Online)
- [x] In-Band BOS Handoff
- [x] Discovery Response & Service List Negotiation
- [x] Defeat the client-side Security / Token Verification
- [x] Full, error-free login run (no crash, no freeze, no error dialog)
- [x] Client reaches ONLINE state (toolbar active, live session)
- [x] Keep the session alive indefinitely (Timeout fully resolved)
- [x] Render the Welcome Screen & Buddy List
- [x] Full content / form rendering

### 🔮 Next Horizons
- [ ] Interactive Chat Rooms & Messaging Channels
- [ ] E-Mail System Simulation (The legendary "You've got mail!" trigger)
- [ ] Keyword Navigation Integration

---

## 💻 Getting Started

### Requirements
* Python 3.x
* An AOL 7.0 Client (English or German) installed on a VM or retro machine
* *(Optional)* GCC / MinGW — the helper module is pre-compiled

### Run
Start the servers, point the client's connection configuration at the local machine, and sign in.

---

## ⚠️ Disclaimer

An independent preservation and research effort for long-discontinued software. Not affiliated with, endorsed by, or connected to AOL. All trademarks belong to their respective owners. Use only with software you are legally entitled to run.

---

## 🏆 Credits & Acknowledgments

Built through patient reverse engineering, live debugging, and a lot of late-night log reading — keeping a piece of internet history alive. 🕹️
