# RAKSHAK.VYUH - Technical Flowchart Explanation Script

## Complete Presentation Text (Hindi + English Mix - Natural Style)

---

## Opening Statement

"RAKSHAK.VYUH ek **four-stage passive analysis pipeline** hai jo IPsec VPN tunnels ki security posture ko evaluate karta hai. Iska sabse important principle hai - **hum kabhi bhi encrypted payload ko decrypt nahi karte**. Sirf handshake ko analyze karte hain. Yeh completely passive hai, zero network intrusion."

---

## Stage 1: Protocol Dissection (Green Box - 01)

**Slide pe point karte hue:**

"Pehla stage hai **Protocol Dissection** - jo humara CipherLens engine handle karta hai.

Yahan pe hum kya kar rahe hain:
- Input ek PCAP file hai - jo already captured traffic hai, offline
- Hum **IKEv1 aur IKEv2 dono protocols** ko parse karte hain using Rust programming language
- Specifically **nom parser combinator library** use kar rahe hain for zero-copy parsing
- SA proposals extract karte hain - matlab konsi encryption algorithms negotiate ho rahi hain
- Transform IDs ko resolve karte hain using **IANA registry** - jo official standard hai

**Key point:** Yeh purely deterministic parsing hai. Koi guesswork nahi, koi ML nahi. Handshake mein jo likha hai, wahi read kar rahe hain."

---

## Stage 2: Compliance Engine (Blue Box - 02)

**Flowchart mein arrow follow karte hue:**

"CipherLens se extracted data ab jaata hai **AttackMap** mein - jo humara compliance engine hai.

Yahan pe magic hota hai:
- Hum **15 specific posture rules** run karte hain - VYU-001 se leke VYU-015 tak
- Har rule ek specific vulnerability check karta hai
- For example:
  - VYU-001: NULL encryption check
  - VYU-002: Weak DH groups like MODP-1024
  - VYU-003: MD5 hash usage
  - VYU-004: 3DES encryption
  - VYU-005: IKEv1 Aggressive Mode

**Sabhi rules RFC-cited hain:**
- RFC 8221 - ESP algorithm recommendations
- RFC 8247 - IKEv2 algorithm implementation
- NIST SP 800-77 - IPsec VPN guidelines

**Important:** Yeh completely deterministic hai. If-else logic hai, no AI inference. Agar rule match hota hai, finding generate hoti hai with severity: Critical, High, Medium, ya Low."

---

## Stage 3: Evidence Ledger (Orange Box - 03)

**Emphasis ke saath:**

"Ab yeh jo findings hain, woh directly **Evidence Ledger** mein jaati hain.

Yeh RAKSHAK.VYUH ka USP hai - **tamper-proof evidence chain**:

1. **SHA-256 hash chaining:** Har ledger entry previous entry ko hash karti hai
2. **PCAP digest binding:** First entry mein complete PCAP file ka digest hai
3. **Packet-level citation:** Har finding exactly batati hai ki:
   - Packet number kya tha
   - Timestamp kya thi
   - Konse SA (Security Association) mein problem thi

**Matlab agar kisi ko doubt ho ki yeh finding sahi hai ya nahi:**
- Woh packet number dekh sakta hai
- Wireshark mein ja kar verify kar sakta hai
- Ledger chain ko validate kar sakta hai

**Tampering impossible hai** because agar koi ek entry change karo, to complete chain break ho jayegi. Hash mismatch ho jayega."

---

## Stage 4: Traffic Intelligence - ML (Purple Box - 04) [Side Branch]

**Side branch pe point karte hue:**

"Yahan pe dekho ek **side branch** hai jo AttackMap se nikalti hai. Yeh humara ML component hai.

**Deliberately alag rakha hai kyunki:**
- Main security scoring ML pe dependent nahi hai
- Yeh sirf **side-channel analysis** ke liye hai

**Kya karta hai:**
- XGBoost aur 1D-CNN ensemble model
- Encrypted ESP traffic mein **packet size aur timing patterns** dekhta hai
- Predict karta hai ki tunnel ke andar konsa application chal raha hai
  - SSH?
  - HTTP?
  - Database traffic?

**Key principle: "Measured, never scored"**
- Matlab yeh traffic pattern detect karta hai
- But security grade ko influence nahi karta
- Report mein separately mention hota hai
- Completely offline inference - no cloud API calls

**Yeh harvest-now-decrypt-later scenarios ko highlight karta hai** - ki agar adversary ne capture kar liya aur future mein quantum computing se decrypt kiya, to konsi information leak ho sakti hai."

---

## Final Output: Grade A-F (Purple Output Box)

**Flow complete karte hue:**

"Sab kuch process hone ke baad, output generate hota hai:

1. **Grade: A se F** - overall tunnel security
   - A: Modern, secure configuration (AES-256-GCM, X25519)
   - B: Acceptable but legacy components (SHA-1)
   - C-D: Weak configurations
   - F: Critical vulnerabilities (NULL encryption, MD5, weak DH)

2. **Multiple export formats:**
   - **JSON** - machine-readable, for automation
   - **HTML** - self-contained report with drill-down
   - **CBOM** (CycloneDX 1.6) - crypto bill of materials for supply chain
   - **Remediation config** - swanctl fragments to fix issues

3. **Air-gapped badge** - yeh emphasize karta hai ki:
   - Zero cloud dependencies
   - Zero telemetry
   - Zero network calls at runtime
   - Complete demo offline chal sakta hai"

---

## Ground Truth Validation (Dataset Box at Bottom)

**Bottom section pe point karte hue:**

"Humne apni methodology ko validate karne ke liye **VYUH corpus** banaya hai - 6 real captures:

**T1: Modern tunnel** (AES-256-GCM, ECP-256) → Grade A
- Industry best practices

**T2: Weak DH** (MODP-1024) → Grade F
- Vulnerable to Logjam attack

**T3: Aggressive Mode IKEv1** (3DES, MD5, PSK) → Grade F
- Multiple critical issues
- PSK can be cracked

**T4: NULL Encryption** (MD5) → Grade F
- No encryption at all
- Only integrity protection

**T5: X25519** (AES-256-GCM) → Grade A
- Modern elliptic curve

**T6: Legacy Integrity** (AES-128-CBC, SHA-1, MODP-2048) → Grade B
- Good DH group but weak hash

**Yeh captures real strongSwan 5.9.13 gateways se generate kiye hain:**
- Docker testbed mein
- Dono sides capture karte hain
- Merge karte hain
- tcpdump output se verify karte hain

**137 automated tests** continuously check kar rahe hain ki parser sahi data extract kar raha hai."

---

## Core Principles Summary (Grey Box Bottom Left)

**Quick recap:**

"Humari methodology 4 core principles pe khadi hai:

1. **Passive-Only**
   - Never decrypt ESP payloads
   - Only handshake analysis
   - No packet injection

2. **Evidence-First**
   - Every finding has proof
   - Packet number citation mandatory
   - No claims without ledger entry

3. **Honest AI**
   - Parser for deterministic fields
   - ML only for traffic patterns
   - No fake confidence scores
   - Unknown reported as unknown

4. **Sovereign**
   - Zero cloud, zero telemetry
   - Air-gapped ready
   - Offline demo certified
   - No external dependencies at runtime"

---

## Technical Stack (Bottom Footer)

"Poora system built hai using:
- **Rust** - core parsing engine (pcap, nom, rayon for parallelism)
- **XGBoost + PyTorch** - ML components
- **DuckDB** - analytical queries on packet data
- **Tauri + React** - desktop dashboard
- **Typst** - report generation
- **SHA-256 + BLAKE3** - cryptographic proofs"

---

## Closing Statement

"To summarize karte hue - RAKSHAK.VYUH ek **end-to-end passive security assessment framework** hai jo:
- ✅ Real-time intrusion ke bina analyze karta hai
- ✅ RFC-compliant rules use karta hai
- ✅ Tamper-proof evidence provide karta hai
- ✅ Quantum-readiness ko evaluate karta hai
- ✅ Completely offline aur air-gapped ready hai

**Yeh na sirf detect karta hai ki problem kya hai, balki exactly bata deta hai ki packet number kitna tha, kab hua, aur kaise fix karna hai.**

Any questions?"

---

## Potential Questions & Answers

### Q: "Agar ESP encrypted hai to traffic pattern kaise detect kar rahe ho?"

**A:** "Encryption packet size aur inter-arrival time ko hide nahi karta. SSH ke packets typically chhote hote hain aur frequent. File transfer ke packets bade hote hain aur burst mein aate hain. Yeh metadata ML model learn karta hai. Payload nahi dekh rahe, sirf packet envelope."

---

### Q: "137 tests automatically run hote hain?"

**A:** "Haan. `cargo test --workspace` run karte hi sab tests execute hote hain. `corpus.rs` specifically 6 captures ko analyze karta hai aur expected findings se match karta hai. Agar parser change kiya aur koi finding miss hui, test fail ho jayega. CI/CD mein integrated hai."

---

### Q: "Real-time analysis possible hai?"

**A:** "Current version offline PCAP analysis karta hai. But architecture streaming-ready hai. `pcap` crate ko `pcap-ng` ya live interface se bhi feed kar sakte hain. Parser zero-copy hai to memory efficient hai. Real-time mein findings console pe stream ho sakti hain."

---

### Q: "Quantum threat kyun mention kar rahe ho?"

**A:** "Harvest-now-decrypt-later attack real hai. Adversary aaj encrypted traffic capture kar leta hai, aur jab quantum computing mature hogi (estimate 10-15 years), wo retrospectively decrypt kar sakta hai. Humara KalScore metric specifically yeh evaluate karta hai ki konse key exchange groups quantum-resistant hain (X25519, Curve25519) aur konse vulnerable (MODP, weak ECC curves)."

---

### Q: "Industry mein already tools hain like Wireshark, Nessus - difference kya hai?"

**A:** 
"Good question. Comparison:

**Wireshark:**
- Packet dissector hai, security analyzer nahi
- User ko manually rules check karne padte hain
- No automated compliance checking
- No evidence ledger

**Nessus/OpenVAS:**
- Active scanning tools hain
- Network pe packets send karte hain
- Production VPN pe risky hai
- Gateway crash ho sakta hai

**RAKSHAK.VYUH:**
- Completely passive - zero network impact
- Automated RFC compliance
- Tamper-proof evidence chain
- Air-gapped environments ke liye designed
- Specific to IPsec VPN, not generic scanner
- CBOM generation for supply chain compliance
- Remediation configs automatically generate karta hai

**Use case:** Defense, BFSI, Critical Infrastructure jahan active scanning allowed nahi hai."

---

### Q: "ML model accuracy kitni hai?"

**A:** "Traffic classification task pe deliberately narrow scope rakha hai. Hum 5-6 common patterns detect kar rahe hain (SSH, HTTP, Database, File Transfer). Lab environment mein 85-90% accuracy mili hai.

**But important note:** Security grade ML pe depend nahi karta. Encryption algorithms, key strengths, protocol versions - yeh sab deterministic parser se milta hai. ML sirf extra context provide karta hai report mein."

---

## Demo Flow (If Asked)

"Quick demo dikhate hain:

```bash
# Analyze a capture
./target/release/vyuh corpus/vyuh-ikev2-modern.pcap

# Output:
# ✓ Parsed 24 packets
# ✓ Found 1 Security Association
# ✓ Grade: A
# ✓ 0 Critical, 0 High, 0 Medium, 0 Low findings
# ✓ Suite: AES-256-GCM, SHA2-256, ECP-256

# Now run on weak capture
./target/release/vyuh corpus/vyuh-ikev1-aggressive-3des.pcap

# Output:
# ✗ Grade: F
# ✗ 3 Critical findings:
#   - VYU-004 (Weak Encryption: 3DES) - Packet #8
#   - VYU-003 (Weak Hash: MD5) - Packet #8  
#   - VYU-002 (Weak DH: MODP-1024) - Packet #12
# ✗ Exit code: 2 (gate failed)

# Full report
./target/release/vyuh corpus/vyuh-ikev1-aggressive-3des.pcap \
  --json report.json \
  --html report.html \
  --ledger ledger.json \
  --remediate fix.conf

# Console dashboard
npm --prefix dashboard run sync
npm --prefix dashboard run dev
# Opens at localhost:5173
```

Dikhate hain findings ko packet number se track kar ke."

---

## End
