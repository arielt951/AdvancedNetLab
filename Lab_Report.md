# Lab Report — Layer 2, Layer 3, and ICMP Implementation
## Advanced Computer Networks Lab (512.4491)

---

## 1. Full Description of Implemented Functions

### 1.1 Layer 2 — L2_impl (Ethernet)

#### `ether_input`

**Description**: Ethernet layer input function. Called by Layer 1 (NIC) when a frame arrives from the network.

**Input Parameters**:
- `m` — `shared_ptr<vector<byte>>` containing the entire packet
- `it` — Iterator pointing to the current position in the vector (past the Ethernet header, positioned by the framework's `leread`)
- `eh` — Pointer to the parsed `ether_header` structure (parsed by the framework)

**Return Value**: `void`

**Functionality**:
1. Reads the `ether_type` field from the Ethernet header. The framework's `leread` function already converts this field from network byte order to host byte order, so no `ntohs()` call is needed.
2. **Self-loop prevention**: If the source MAC address matches our NIC's MAC address, the frame is silently dropped. This prevents processing of frames reflected back by the pcap sniffer.
3. **Demultiplexing** based on the EtherType field:
   - `ETHERTYPE_IP` (0x0800): Passes the packet up to Layer 3 by looking up the IP protocol handler via `inet.inetsw(SWPROTO_IP)` and calling `pr_input`.
   - `ETHERTYPE_ARP` (0x0806): Passes the packet to the ARP module via `inet.arp()->in_arpinput()`.
   - Default: Drops the packet silently.

```cpp
void L2_impl::ether_input(shared_ptr<vector<byte>> &m, vector<byte>::iterator &it,
                          struct ether_header *eh) {
    u_short ether_type = eh->ether_type;  // already in host byte order
    
    // Self-loop prevention: drop our own reflected frames
    if (eh->ether_shost == inet.nic()->mac()) return;
    
    switch (ether_type) {
    case ETHERTYPE_IP:  // 0x0800 → pass to L3 (pr_input)
    case ETHERTYPE_ARP: // 0x0806 → pass to ARP module
    default:            // drop unknown types
    }
}
```

#### `ether_output`

**Description**: Ethernet layer output function. Called by Layer 3 when a packet needs to be transmitted.

**Input Parameters**:
- `m` — `shared_ptr<vector<byte>>` containing the packet buffer
- `it` — Iterator to the current position in the buffer
- `dst` — `sockaddr` structure containing the destination address and address family (`AF_INET` or `AF_UNSPEC`)
- `rt0` — Routing entry (may be null)

**Return Value**: `void`

**Functionality**:
1. **Identify packet type** based on `dst->sa_family`:
   - `AF_INET` (IP packet): Resolves the destination IP to a MAC address via `arpresolve()`. If ARP resolution is pending, the function returns (the packet is queued by ARP). Sets `ether_type = htons(ETHERTYPE_IP)` — `htons` is required because the wire format uses network byte order and `lestart` writes bytes as-is.
   - `AF_UNSPEC` (ARP packet): Uses the pre-built Ethernet header embedded in `dst->sa_data` by the ARP module. The `ether_type` is already in network byte order.
2. **Build the Ethernet header**: Writes the destination MAC, source MAC (from `inet.nic()->mac()`), and ether_type at the beginning of the buffer (`m->begin()`).
3. **Pad to minimum size**: If the data portion is less than 46 bytes (ETHERMIN), the buffer is zero-padded to 60 bytes total (the minimum Ethernet frame size excluding CRC).
4. **Transmit via L1**: Calls `inet.nic()->lestart()` to inject the frame onto the physical adapter via pcap (allows Wireshark capture).
5. **Virtual cable delivery**: If a peer L2_impl is configured, creates a copy of the frame, converts the `ether_type` from network to host byte order (simulating what `leread` does), advances the iterator past the Ethernet header, and calls `peer->ether_input()` directly.

```cpp
void L2_impl::ether_output(shared_ptr<vector<byte>> &m, vector<byte>::iterator &it,
                           struct sockaddr *dst, struct L3::rtentry *rt0) {
    if (dst->sa_family == AF_INET) {
        mac_addr *resolved = inet.arp()->arpresolve(m, it, 0, dst);
        if (!resolved) return;  // ARP pending
        ether_type = htons(ETHERTYPE_IP);
    } else if (dst->sa_family == AF_UNSPEC) {
        // Pre-built Ethernet header from ARP module
    }
    // Write Ethernet header at m->begin()
    // Pad to minimum 60 bytes
    // Send via lestart (for Wireshark) + virtual cable (for reliable delivery)
}
```

---

### 1.2 Layer 3 — L3_impl (IP)

#### `pr_input`

**Description**: IP layer input function. Called by Layer 2 when an IP packet is received.

**Input Parameters**:
- `args` — `pr_input_args` structure containing:
  - `m` — The packet buffer
  - `it` — Iterator pointing to the start of the IP header (the framework's `leread` already positioned it past the 14-byte Ethernet header)
  - `iphlen` — IP header length (calculated inside the function)

**Return Value**: `void`

**Functionality — Validation Chain**:
1. **IP Version**: Checks that `ip_v_hl.hb == 4` (must be IPv4). Drops otherwise.
2. **Header Length**: Computes `hlen = ip_v_hl.lb << 2` (IHL field × 4). Must be ≥ 20 bytes (`sizeof(iphdr)`). Drops otherwise.
3. **Total Length**: Checks that `ntohs(ip_len) >= hlen`. Drops otherwise.
4. **Checksum**: Calls `in_cksum()` over the IP header bytes. Result must be 0. Drops otherwise.
5. **Protocol**: Checks that `ip_p == IPPROTO_ICMP` (1). Drops non-ICMP traffic (TCP=6, UDP=17, etc.).
6. **Destination IP**: Checks that `ip_dst.s_addr` matches our NIC's IP address or the broadcast address `0xFFFFFFFF`. Drops otherwise.

If all validations pass:
- Advances the iterator past the IP header (`it += hlen`)
- Extracts the sender's IP address from `ip_src`
- Calls `inet.getICMP()->recvFromL4()` to pass the ICMP payload up to Layer 4

**Important design note**: The iterator is NOT advanced past the Ethernet header inside this function — the framework's `leread` already handles that. Doing it twice would cause the IP header to be read from offset 28 instead of 14, resulting in corrupted field values.

```cpp
void L3_impl::pr_input(const struct pr_input_args &args) {
    struct iphdr* ip = reinterpret_cast<struct iphdr*>(&(*it));
    
    if (ip->ip_v_hl.hb != 4) return;           // version check
    hlen = ip->ip_v_hl.lb << 2;
    if (hlen < sizeof(iphdr)) return;           // header length check
    if (ntohs(ip->ip_len) < hlen) return;       // total length check
    if (in_cksum(&(*it), hlen) != 0) return;    // checksum check
    if (ip->ip_p != IPPROTO_ICMP) return;       // protocol check
    if (ip->ip_dst.s_addr != our_ip) return;    // destination check
    
    it += hlen;  // advance past IP header
    inet.getICMP()->recvFromL4(sendData, sendDataLen, destIP);
}
```

#### `ip_output` (via `pr_output`)

**Description**: IP layer output function. Called by Layer 4 when an IP packet needs to be sent.

**Input Parameters**:
- `args` — `ip_output_args` structure containing:
  - `m` — The packet buffer (with space pre-allocated for L2 and L3 headers)
  - `it` — Iterator
  - `ro` — Route structure with `ro_dst` containing the destination IP address
  - `opt` — IP options (unused)
  - `flags` — Output flags (unused)

**Return Value**: `int` — 0 on success

**Functionality**:
1. **Position the iterator** at `m->begin() + sizeof(ether_header)` (offset 14) — this is where the IP header starts.
2. **Fill the IP header fields**:
   - `ip_v_hl.hb = 4` (IPv4)
   - `ip_v_hl.lb = 5` (20 bytes / 4 = 5 words)
   - `ip_tos = 0`
   - `ip_len = htons(total_size - sizeof(ether_header))`
   - `ip_id = htons(++ip_id)` — auto-incrementing packet ID
   - `ip_off = 0` (no fragmentation)
   - `ip_ttl = 64`
   - `ip_p = IPPROTO_ICMP`
   - `ip_src = inet.nic()->ip_addr()`
   - `ip_dst` from `args.ro->ro_dst`
3. **Compute the checksum**: `ip_sum = in_cksum(&(*it), hlen)` (one's complement sum over the 20-byte header)
4. **Gateway routing**: Compares `(target_ip & netmask)` with `(our_ip & netmask)`:
   - **Internal** (same subnet): The L2 next-hop stays as the destination IP itself
   - **External** (different subnet): Overwrites the `ro_dst` with the default gateway IP so that L2 performs ARP resolution against the gateway instead
5. **Pass down to Layer 2**: Calls `ether_output(m, it, &ro->ro_dst, ro->ro_rt)`

```cpp
int L3_impl::ip_output(const struct ip_output_args &args) {
    it = m->begin() + sizeof(ether_header);
    struct iphdr* ip = reinterpret_cast<struct iphdr*>(&(*it));
    
    // Fill IP header: version, IHL, TTL, protocol, src IP, dst IP...
    ip->ip_sum = in_cksum(&(*it), hlen);
    
    // Routing decision
    if ((target_ip & mask) != (my_ip & mask)) {
        ro_dst->sin_addr.s_addr = gateway;  // external → route via gateway
    }
    
    inet.datalink()->ether_output(m, it, &ro->ro_dst, ro->ro_rt);
    return 0;
}
```

---

### 1.3 ICMP Layer — L4 (L4_ICMP_impl)

#### `sendToL4`

**Description**: Constructs an ICMP message and sends it down through Layer 3.

**Input Parameters**:
- `sendData` — Pointer to the payload data (up to 50 bytes)
- `sendDataLen` — Length of the payload
- `destIP` — Destination IP address (string)
- `srcIP` — Source IP address (string, unused — source is set by L3)
- `flag` — ICMP message type: `ECHO_REQUEST` (type 8) or `ECHO_REPLY` (type 0)

**Return Value**: `int` — result of `pr_output`

**Functionality**:
1. Creates an ICMP packet using the libtins library (`Tins::ICMP(flag)`) and appends the payload as a `RawPDU`.
2. Serializes the ICMP packet into a byte vector (includes type, code, checksum, identifier, sequence number, and data).
3. Allocates a full packet buffer: `sizeof(ether_header) + sizeof(iphdr) + ICMP_size`.
4. Copies the serialized ICMP data into the buffer at the correct offset (after L2 and L3 header space).
5. Configures the routing structure with `dest_addr->sin_addr.s_addr = inet_addr(destIP)`.
6. Calls `pr_output()` which invokes `ip_output` on Layer 3.

#### `recvFromL4`

**Description**: Receives an incoming ICMP message that arrived from the network through Layer 3.

**Input Parameters**:
- `sendData` — Pointer to the ICMP data (after the IP header has been stripped by L3)
- `sendDataLen` — Length of the ICMP data
- `destIP` — Source IP address of the sender (used as the destination for replies)

**Return Value**: `int` — length of data processed

**Functionality**:
1. Parses the incoming ICMP packet using libtins (`Tins::ICMP(sendData, sendDataLen)`).
2. Validates the ICMP type — must be `ECHO_REQUEST` or `ECHO_REPLY`. Drops all other types.
3. Extracts the raw payload from the ICMP packet.
4. Stores the payload in the internal `recvPacket` buffer (freeing any previous buffer).
5. **If ECHO_REQUEST**: Automatically sends an ECHO_REPLY back to the sender by calling `sendToL4(recvPacket, recvPacketLen, destIP, "", ECHO_REPLY)`.
6. **If ECHO_REPLY**: Unlocks `recvPacket_mutex` so that the blocking `readFromL4` function (in the main thread) can read the response. Then re-locks the mutex to prepare for the next packet.

---

## 2. Module Details and Data Structures

### 2.1 Key Data Structures

| Structure | Layer | Description | Size |
|-----------|-------|-------------|------|
| `ether_header` | L2 | Ethernet frame header: destination MAC, source MAC, ether_type | 14 bytes |
| `iphdr` | L3 | IP header: version/IHL, TOS, total length, ID, flags/offset, TTL, protocol, checksum, src IP, dst IP | 20 bytes (no options) |
| `ICMP` (libtins) | L4 | ICMP header: type (1B), code (1B), checksum (2B), identifier (2B), sequence number (2B) | 8 bytes |
| `mac_addr` (`HWAddress<>`) | L2 | 6-byte MAC address | 6 bytes |
| `sockaddr_in` | L3 | Socket address: sin_family, sin_port, sin_addr | 16 bytes |
| `route` | L3 | Routing info: `ro_dst` (destination sockaddr), `ro_rt` (routing table entry) | variable |

### 2.2 Virtual Cable Module

We implemented a "virtual cable" mechanism that enables direct in-memory communication between two virtual NIC instances. This was necessary because Windows Wi-Fi adapters do not support pcap loopback — frames injected via `pcap_sendpacket` are not captured back by the sniffer on the same adapter.

**Global Variables**:
- `g_peer_a`, `g_peer_b` — Pointers to the two connected `L2_impl` instances

**Functions**:
- `L2_impl_set_peers(a, b)` — Links two peers together
- `get_peer(self)` — Returns the peer of a given instance

**How it works**: When `ether_output` sends a frame, it:
1. Calls `lestart()` to inject the frame via pcap (for Wireshark visibility)
2. Creates a copy of the frame buffer
3. Converts `ether_type` from network to host byte order (simulating `leread`)
4. Advances the iterator past the Ethernet header (simulating `leread`)
5. Calls `peer->ether_input()` directly with the copied frame

### 2.3 Main Module

The `main.cpp` defines three test scenarios selectable via an interactive menu:

| Scenario | Client | Server | Routing | Purpose |
|----------|--------|--------|---------|---------|
| **A** | 10.0.0.15/24 (gw: 10.0.0.1) | 20.0.0.10/24 (gw: 20.0.0.1) | External (via gateway) | Send ICMP to IP outside our subnet |
| **B** | 10.0.0.15/24 | 10.0.0.10/24 | Internal (direct) | Send ICMP to IP inside our subnet |
| **C** | 10.0.0.15/24 (receives) | 10.0.0.10/24 (sends) | Internal (direct) | Receive ICMP and send reply |

Each scenario initializes two `inet_os` instances with complete L2/L3/L4 stacks, pre-populated ARP tables (static entries), and a virtual cable connection.

### 2.4 Byte Order Convention

| Location | Byte Order | Reason |
|----------|-----------|--------|
| Wire (Ethernet frame) | Network (big-endian) | IEEE 802.3 standard |
| `leread` output / `ether_input` input | **Host** (little-endian on x86) | Framework converts automatically |
| `ETHERTYPE_IP/ARP` constants | **Host** | Defined as `0x0800`, `0x0806` |
| `ether_output` → `eh->ether_type` | **Network** | Must match wire format for `lestart` |
| Virtual cable `eh_copy->ether_type` | **Host** | We convert with `ntohs()` to simulate `leread` |

---

## 3. Running Examples and Analysis

### 3.1 Example A — ICMP REQUEST to IP Address NOT in Our Subnet (External Ping)

**Configuration**: Client `10.0.0.15/24` (gateway: `10.0.0.1`) → Server `20.0.0.10/24` (gateway: `20.0.0.1`)

**📸 [INSERT SCREENSHOT: Console output for Scenario A — showing "External target -> routing via gateway"]**

**📸 [INSERT SCREENSHOT: Wireshark capture for Scenario A — showing ICMP request 10.0.0.15 → 20.0.0.10 and reply 20.0.0.10 → 10.0.0.15]**

**Detailed Packet Flow Analysis**:

**Sending the ECHO REQUEST**:
1. `main` calls `ICMP_client.sendToL4("NetlabPingPongTest", "20.0.0.10", ECHO_REQUEST)`
2. **L4 (sendToL4)**: Builds an ICMP ECHO_REQUEST using libtins, serializes it, allocates a full buffer (14 + 20 + ICMP bytes), copies the ICMP payload after the L2/L3 header space, sets up the route with destination 20.0.0.10, and calls `pr_output`.
3. **L3 (ip_output)**: Fills the IP header — src=10.0.0.15, dst=20.0.0.10, protocol=ICMP, TTL=64. Computes the IP header checksum. **Routing check**: `(20.0.0.10 & 255.255.255.0) = 20.0.0.0` ≠ `(10.0.0.15 & 255.255.255.0) = 10.0.0.0` → **External target!** Overwrites the L2 next-hop to gateway `10.0.0.1`. Calls `ether_output`.
4. **L2 (ether_output)**: Address family is `AF_INET` → ARP resolves 10.0.0.1 → returns MAC `aa:aa:aa:aa:aa:aa` (static entry). Builds the Ethernet header (dst=aa:aa:aa:aa:aa:aa, src=bb:bb:bb:bb:bb:bb, type=0x0800). Pads to 60 bytes. Sends via `lestart` and virtual cable.

**Reception and Reply by Server (ECHO REPLY)**:
5. **L2 Server (ether_input)**: Receives the frame via virtual cable. ether_type=0x0800 (IP) → passes to L3.
6. **L3 Server (pr_input)**: Validation chain: version=4 ✓, hlen=20 ✓, checksum ✓, protocol=ICMP ✓, dst=20.0.0.10 == our_ip=20.0.0.10 ✓ → **ACCEPTED**.
7. **L4 Server (recvFromL4)**: Parses ICMP — type=ECHO_REQUEST → automatically sends ECHO_REPLY back to 10.0.0.15 via `sendToL4`.
8. **L3 Server (ip_output)**: src=20.0.0.10, dst=10.0.0.15. Routing: `10.0.0.15` not in `20.0.0.0/24` → **External** → next-hop = gateway 20.0.0.1.
9. **L2 Server (ether_output)**: ARP resolves 20.0.0.1 → `bb:bb:bb:bb:bb:bb`. Sends via virtual cable.

**Reception of Reply by Client**:
10. **L2 Client (ether_input)**: ether_type=0x0800 → L3.
11. **L3 Client (pr_input)**: dst=10.0.0.15 == our_ip ✓ → **ACCEPTED**.
12. **L4 Client (recvFromL4)**: type=ECHO_REPLY → stores in buffer, unlocks mutex ← **Ping succeeded!**

---

### 3.2 Example B — ICMP REQUEST to IP Address IN Our Subnet (Internal Ping)

**Configuration**: Client `10.0.0.15/24` → Server `10.0.0.10/24` (same subnet, no gateway needed)

**📸 [INSERT SCREENSHOT: Console output for Scenario B — showing "Internal target -> direct routing"]**

**📸 [INSERT SCREENSHOT: Wireshark capture for Scenario B — showing ICMP request 10.0.0.15 → 10.0.0.10 and reply]**

**Detailed Packet Flow Analysis**:

**Sending the ECHO REQUEST**:
1. `main` calls `ICMP_client.sendToL4("NetlabPingPongTest", "10.0.0.10", ECHO_REQUEST)`
2. **L4 (sendToL4)**: Same as Example A — builds ICMP, allocates buffer, sets route to 10.0.0.10.
3. **L3 (ip_output)**: Fills IP header — src=10.0.0.15, dst=10.0.0.10. **Routing check**: `(10.0.0.10 & 255.255.255.0) = 10.0.0.0` == `(10.0.0.15 & 255.255.255.0) = 10.0.0.0` → **Internal target!** The L2 next-hop remains `10.0.0.10` (no gateway redirection). Calls `ether_output`.
4. **L2 (ether_output)**: ARP resolves `10.0.0.10` directly → MAC `aa:aa:aa:aa:aa:aa`. Sends.

**Reception and Reply**: Steps 5–12 are identical to Example A, except the Server's reply routing is also **Internal** (both are in `10.0.0.0/24`).

**Key Difference from Example A**: In L3's routing logic, the destination `10.0.0.10` is in the same `/24` subnet as the client `10.0.0.15`. Therefore, ARP resolution is performed on the destination IP directly, not on the gateway address. The console output shows `"Internal target -> direct routing"` instead of `"External target -> routing via gateway"`.

---

### 3.3 Example C — Receive ICMP REQUEST from IP in Our Subnet and Send Reply

**Configuration**: Server `10.0.0.10/24` sends ping → Client `10.0.0.15/24` receives and auto-replies

**📸 [INSERT SCREENSHOT: Console output for Scenario C — showing Server sends ECHO_REQUEST, Client receives and sends ECHO_REPLY]**

**📸 [INSERT SCREENSHOT: Wireshark capture for Scenario C — showing ICMP request 10.0.0.10 → 10.0.0.15 and reply 10.0.0.15 → 10.0.0.10]**

**Detailed Packet Flow Analysis**:

**Server Sends ECHO REQUEST**:
1. `main` calls `ICMP_server.sendToL4("NetlabPingPongTest", "10.0.0.15", ECHO_REQUEST)`
2. **L4 Server (sendToL4)**: Builds ICMP ECHO_REQUEST, sets route to 10.0.0.15.
3. **L3 Server (ip_output)**: src=10.0.0.10, dst=10.0.0.15. Internal routing (same subnet).
4. **L2 Server (ether_output)**: ARP resolves 10.0.0.15 → `bb:bb:bb:bb:bb:bb`. Sends via virtual cable.

**Client Receives and Auto-Replies**:
5. **L2 Client (ether_input)**: ether_type=0x0800 → passes to L3.
6. **L3 Client (pr_input)**: version=4 ✓, hlen=20 ✓, checksum ✓, protocol=ICMP ✓, dst=10.0.0.15 == our_ip ✓ → **ACCEPTED**.
7. **L4 Client (recvFromL4)**: type=ECHO_REQUEST → **Automatically sends ECHO_REPLY** back to 10.0.0.10 via `sendToL4`.
8. **L3 Client (ip_output)**: src=10.0.0.15, dst=10.0.0.10. Internal routing.
9. **L2 Client (ether_output)**: ARP resolves 10.0.0.10 → `aa:aa:aa:aa:aa:aa`. Sends.

**Server Receives the Reply**:
10. **L2 Server (ether_input)**: ether_type=0x0800 → L3.
11. **L3 Server (pr_input)**: dst=10.0.0.10 == our_ip ✓ → **ACCEPTED**.
12. **L4 Server (recvFromL4)**: type=ECHO_REPLY → stores in buffer, unlocks mutex ← **Reply received!**

**Key Point**: This example demonstrates the system's ability to **receive** an incoming ICMP ECHO_REQUEST and **automatically respond** with an ECHO_REPLY — exactly as a real operating system responds to a `ping` command.

---

## 4. Assumptions, Known Issues, and Notes

### Assumptions
- The system runs in Virtual OS mode with two `inet_os` instances in the same process, connected via a virtual cable
- ARP tables are pre-populated with static entries (no real ARP resolution over the network)
- Routing is limited to simple gateway-based routing (no complex routing tables)
- Only ICMP ECHO_REQUEST and ECHO_REPLY messages are supported (protocol filter in L3)

### Known Issues
1. **Network Noise**: The pcap sniffer threads capture real traffic from the Wi-Fi adapter (TCP, UDP, ARP broadcasts, etc.). This traffic is correctly dropped by the L3 validation (protocol ≠ ICMP, or destination IP mismatch), but it produces "DROPPED" log messages in the console.
2. **Duplicate Frames**: In some cases, a frame may be received twice — once from the virtual cable and once from the pcap sniffer. This does not cause an infinite loop because `recvFromL4` only sends ECHO_REPLY in response to ECHO_REQUEST (not in response to another ECHO_REPLY).
3. **`inet_ntoa` Static Buffer**: The `inet_ntoa` function returns a pointer to a shared static buffer. Multiple calls in the same `<<` chain would overwrite each other. This was resolved by capturing each IP address into a separate `std::string` before printing.

### Design Decisions
- **Virtual Cable**: Implemented because WinPcap/Npcap on Windows Wi-Fi adapters does not support loopback of injected frames. The virtual cable guarantees delivery between the two virtual NICs.
- **`htons` on Output, No `ntohs` on Input**: The framework's `leread` converts `ether_type` to host byte order before calling `ether_input`, so no conversion is needed on input. On output, `htons` is required because `lestart` writes bytes to the wire as-is.
- **Dual Transmission (lestart + virtual cable)**: `lestart` is called so that Wireshark can capture the frames on the Wi-Fi adapter. The virtual cable ensures the frame is reliably delivered to the peer NIC regardless of pcap loopback behavior.
