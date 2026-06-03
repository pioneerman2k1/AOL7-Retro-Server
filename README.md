# AOL 7.0 Retro Server

A Python-based server emulator for the vintage **AOL 7.0 Client (2001)**, reviving the proprietary P3 protocol and driving the old client all the way through login, the security handshake, and into a live **online session** — entirely against local emulation servers.

---

## 📖 About The Project

This project resurrects the AOL 7.0 Client by reverse-engineering the server-side infrastructure. Unlike standard AIM clients that speak OSCAR directly, the full AOL client wraps everything in a heavily encrypted, proprietary protocol called **P3**.

For years the AOL 7.0 client got stuck at the *"Handshake"* / *"Verifying Password"* stage, because the P3 mechanism and the client's internal security engine (`sec.cct`) were undocumented. This project now drives the client cleanly through the **entire login sequence and into an online session** — handshake, session setup, the security challenge, buddy-list/online-status, and the post-login data stream — without crashes or error dialogs.

*Strictly for educational and preservation purposes.*

---

## 🚀 Current Status — v0.9.0 *"Online & Live Session"*

The client now completes a **full, error-free login** and **goes online** against the emulator:

- ✅ **Two-Server Architecture** — seamless handoff between the Login server (port 5190) and the BOS server (port 5194).
- ✅ **In-Band Proxy Tunneling** — transparent proxying of the secondary handshake over the existing connection.
- ✅ **Stable, fast handshake** — connection establishes in well under a second.
- ✅ **Full session setup** — login confirmation, screen name, message-of-the-day, buddy-list init and online status are all accepted.
- ✅ **🔥 Security Handshake passed** — the `sec.cct` security challenge (the part that blocked everyone for years) is satisfied. No *"AOL Error 040"*, no abrupt disconnect.
- ✅ **🎉 The client goes ONLINE** — the toolbar lights up (Mail, Chat, Groups, SMS, Banking…), the secure session stays alive, and the client actively asks the host to *show its Welcome content*.
- ✅ **Clean run** — no crash, no freeze during the session, no error pop-ups.

> In short: we went from *"the client refuses every connection"* to *"the client logs in, passes security, goes online, and asks for its Welcome screen."*

---

## 🧩 The Big Breakthroughs

1. **Most disconnects were self-inflicted** — the emulator's own packets were tripping a built-in client safety check. Fixing that single root cause let the client glide through the login it had refused for two decades.
2. **The security session was being torn down too early** — neutralizing that kept the secure session alive through the whole run.
3. **The client tells us what it wants** — once online it fires an in-band request for its Welcome content, exactly like it would against the real AOL service.

---

## 🗺 Roadmap

- [x] Stable P3 Handshake & Identity Mirroring
- [x] State Machine Advance (Auth → Online)
- [x] In-Band BOS Handoff
- [x] Discovery Response & Service List Negotiation
- [x] **Defeat the client-side Security / Token Verification (`sec.cct`)**
- [x] Full, error-free login run (no crash, no freeze, no error dialog)
- [x] **Client reaches ONLINE state (toolbar active, live session)**
- [ ] Keep the session alive indefinitely *(currently stable ~40s, then the client retries)*
- [ ] Render the Welcome Screen & Buddy List
- [ ] Full content / form rendering

> **Known limitation:** the secure handshake is *accepted* but not *cryptographically completed* (that needs the original AOL keys). The client therefore re-tries establishment after ~40 seconds. Work in progress: delivering the Welcome content so the client settles, and/or completing the secure layer.

---

## 💻 Getting Started

**Requirements**

- Python 3.x
- An **AOL 7.0 Client** (English or German) installed on a VM or retro machine
- (Optional) GCC / MinGW — the helper module is pre-compiled

**Run**

Start the three servers (Login, BOS, HTTP), point the client's connection at the local machine, and sign in.

---

## ⚠️ Disclaimer

An independent preservation and research effort for long-discontinued software. **Not affiliated with, endorsed by, or connected to AOL.** All trademarks belong to their respective owners. Use only with software you are legally entitled to run.

---

## 🏆 Credits & Acknowledgments

Built through patient reverse engineering, live debugging and a lot of late-night log reading — keeping a piece of internet history alive. 🕹️
