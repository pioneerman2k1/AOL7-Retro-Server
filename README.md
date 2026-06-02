# AOL 7.0 Retro Server

A Python-based server emulator for the vintage **AOL 7.0 Client (2001)**, reviving the proprietary P3 protocol and getting the old client all the way through login again — entirely against local emulation servers.

---

## 📖 About The Project

This project aims to resurrect the AOL 7.0 Client by reverse-engineering the server-side infrastructure. Unlike standard AIM clients that talk OSCAR directly, the full AOL client wraps everything in a heavily encrypted, proprietary protocol called **P3**.

For years the AOL 7.0 client got stuck at the *"Handshake"* or *"Verifying Password"* stage, because the P3 mechanism and the client's internal security engine (`sec.cct`) were completely undocumented. This project now drives the client cleanly through the **entire login sequence** — handshake, session setup, the security challenge, and the post-login data stream — without crashes, freezes or error dialogs.

*Strictly for educational and preservation purposes.*

---

## 🚀 Current Status — v0.8.0 *"Secure Handshake Conquered"*

The client now completes a **full, error-free login run** against the emulator:

- ✅ **Two-Server Architecture** — seamless handoff between the Login server (port 5190) and the BOS server (port 5194).
- ✅ **In-Band Proxy Tunneling** — transparent proxying of the secondary handshake over the existing connection.
- ✅ **Stable, fast handshake** — the old multi-second stalls are gone; the connection now establishes in well under a second.
- ✅ **Full session setup** — login confirmation, screen name, message-of-the-day, buddy-list init and online status are all accepted by the client.
- ✅ **🔥 Security Handshake solved** — the client's `sec.cct` security challenge (the part that blocked everyone for years) now completes successfully. No more *"AOL Error 040"*, no abrupt disconnect.
- ✅ **Clean shutdown** — the client behaves normally and closes properly instead of freezing.
- ✅ **Client reaches the post-login stage** — it fires its navigation request and asks the server to *"show mail and buddy list"*, exactly like it would against the real AOL service.

> In short: we went from *"the client refuses the connection"* to *"the client logs in, passes security, and actively asks for its welcome content."*

---

## 🧩 The Big Breakthrough

The key turning point was realizing that **most of the disconnects were self-inflicted** — the emulator's own packets were tripping a built-in client safety check. Once that was understood, the whole picture changed: instead of fighting a dozen symptoms, we fixed the single root cause in the security layer. After that, the client glided through the login it had been refusing for two decades.

---

## 🗺 Roadmap

- [x] Stable P3 Handshake & Identity Mirroring
- [x] State Machine Advance (Auth → Online)
- [x] In-Band BOS Handoff
- [x] Discovery Response & Service List Negotiation
- [x] **Defeat the client-side Security / Token Verification (`sec.cct`)** — *done!*
- [x] Full, error-free login run (no crash, no freeze, no error dialog)
- [ ] Display the Welcome Screen & Buddy List *(the final step — in progress)*
- [ ] Full content / form rendering

---

## 💻 Getting Started

**Requirements**

- Python 3.x
- An **AOL 7.0 Client** (English or German) installed on a VM or a retro machine
- (Optional) GCC / MinGW — the helper module is already pre-compiled

**Run**

Start the three servers (Login, BOS, HTTP), point the client's connection at the local machine, and sign in.

---

## ⚠️ Disclaimer

This project is an independent preservation and research effort for a long-discontinued piece of software. It is **not affiliated with, endorsed by, or connected to AOL** in any way. All trademarks belong to their respective owners. Use it only with software you are legally entitled to run.

---

## 🏆 Credits & Acknowledgments

Built through patient reverse engineering, live debugging and a lot of late-night log reading — keeping a piece of internet history alive. 🕹️
