import random
import hashlib
import os
import socket
import struct
from cryptography.hazmat.primitives.asymmetric import dh

class RC4State:
    def __init__(self, key):
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def crypt(self, data):
        out = bytearray(len(data))
        for k in range(len(data)):
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.S[self.i]) % 256
            self.S[self.i], self.S[j] = self.S[j], self.S[i]
            out[k] = data[k] ^ self.S[(self.S[self.i] + self.S[self.j]) % 256]
        return bytes(out)

    def discard(self, n):
        dummy = bytearray(n)
        self.crypt(dummy)

class HandshakeHandler:

    P_HEX = (
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B225"
        "14A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F"
        "44C42E9A63A36210000000000090563"
    )
    P_INT = int(P_HEX, 16)
    G_INT = 2

    def __init__(self, console, peer_ip, peer_port, enable_plain=True):
        self.console = console
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self.enable_plain = enable_plain

    def recv_exactly(self, s, num_bytes):
        buf = b''
        while len(buf) < num_bytes:
            try:
                data = s.recv(num_bytes - len(buf))
                if not data:
                    return None
                buf += data
            except socket.error:
                return None
        return buf

    """
    Performs a plain (non-encrypted) handshake with the peer.
    """
    def plain_handshake(self, socket, info_hash):
        try:
            protocol_name = b'BitTorrent protocol'
            reserved_bytes = b'\x00' * 8
            handshake_message = (
                bytes([19]) + protocol_name + reserved_bytes + info_hash + self.peer_id
            )

            socket.sendall(handshake_message)
            peer_handshake = self.recv_exactly(socket, len(handshake_message))
            if not peer_handshake or peer_handshake[28:48] != info_hash:
                self.console.log(f"[red]Plain handshake failed or info hash mismatch[/]")
                return False

            self.console.log(f"[green]Plain handshake successful[/]")
            return True

        except Exception as e:
            self.console.log(f"[red]Error during plain handshake: {e}[/]")
            return False

    """
    State machine for MSE/PE:
    State A: Send Ya+PadA, receive Yb
    State B: Send req1/req2xorreq3, search for VC in the stream
    State C: Process crypto_select, PadB, IA
    State D: Derive RC4 keys, send final payload (VC+crypto_provide+PadC+IB)
    """
    def encrypted_handshake(self, s, info_hash):

        # Hash functions
        def sha1_bytes(x):
            return hashlib.sha1(x).digest()

        # State A: Generate and send Ya+PadA, receive Yb
        params = dh.DHParameterNumbers(self.P_INT, self.G_INT).parameters()
        private_key = params.generate_private_key()
        Ya = private_key.public_key().public_numbers().y
        Ya_bytes = Ya.to_bytes(96, 'big')
        PadA_length = random.randint(0, 512)
        PadA = os.urandom(PadA_length)
        self.console.log("[cyan]State A: Sending Ya+PadA[/]")
        s.sendall(Ya_bytes + PadA)

        self.console.log("[cyan]State A: Waiting for Yb (96 bytes)[/]")
        Yb_bytes = self.recv_exactly(s, 96)
        if not Yb_bytes:
            self.console.log("[red]Could not receive 96 bytes of Yb. Aborting MSE handshake.[/]")
            return None
        Yb = int.from_bytes(Yb_bytes, 'big')
        self.console.log("[cyan]State A: Yb received. Calculating secret S[/]")
        peer_public_numbers = dh.DHPublicNumbers(Yb, params.parameter_numbers())
        peer_public_key = peer_public_numbers.public_key()
        S = private_key.exchange(peer_public_key)
        SKEY = info_hash

        req1 = sha1_bytes(b'req1' + S)
        req2 = sha1_bytes(b'req2' + SKEY)
        req3 = sha1_bytes(b'req3' + S)

        # State B: Send req1 and req2xorreq3, then search for VC
        self.console.log("[cyan]State B: Sending req1(S) and req2xorreq3[/]")
        #s.sendall(req1)
        req2_xor_req3 = bytes(a ^ b for a, b in zip(req2, req3))
        #s.sendall(req2_xor_req3)
        s.sendall(req1 + req2_xor_req3)

        self.console.log("[cyan]State B: Searching for VC in the stream (up to 1024 bytes)[/]")
        
        VC = b'\x00' * 8
        crypto_provide = b'\x00\x00\x00\x03'
        PadC_length = random.randint(0, 512)
        PadC = os.urandom(PadC_length)

        bt_handshake = (
            bytes([19]) + b'BitTorrent protocol' + 
            b'\x00' * 8 + info_hash + self.peer_id
        )
        len_IB = struct.pack(">H", len(bt_handshake))
        payload = VC + crypto_provide + PadC + len_IB + bt_handshake

        if chosen == 0x02:
            payload = rc4_out.crypt(payload)

        s.sendall(payload)

        buffer = b''
        for i in range(1024):
            try:
                data = s.recv(1)
                if not data:
                    break
                buffer += data
            except socket.error:
                break
        found_vc_index = buffer.find(VC)

        if found_vc_index == -1:
            self.console.log("[yellow]VC not found after 1024 bytes. Peer does not support MSE or is not responding.[/]")
            if self.enable_plain:
                self.console.log("[yellow]Attempting fallback to plain handshake...[/]")
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((self.peer_ip, self.peer_port))
                if self.plain_handshake(s, info_hash):
                    self.console.log("[green]Fallback to plain handshake successful.[/]")
                    return {'rc4_in': None, 'rc4_out': None, 'initial_bt_handshake': b''}
                else:
                    self.console.log("[red]Fallback to plain handshake failed.[/]")
                    return None
            return None

        self.console.log("[cyan]State B: VC found. Processing crypto_select, PadB, and IA.[/]")
        buffer = buffer[found_vc_index:]
        # We need at least 8+4 = 12 bytes: VC(8) + crypto_select(4)
        if len(buffer) < 12:
            needed = 12 - len(buffer)
            extra = self.recv_exactly(s, needed)
            if not extra:
                self.console.log("[red]Could not read crypto_select after VC.[/]")
                return None
            buffer += extra

        crypto_select = buffer[8:12]
        chosen = int.from_bytes(crypto_select, 'big') & 0x03
        if chosen not in (0x01, 0x02):
            self.console.log("[red]Peer does not offer a supported encryption. Aborting.[/]")
            return None
        
        if chosen & 0x02:
            chosen = 0x02
            self.console.log("[cyan]RC4 chosen[/]")
        elif chosen & 0x01:
            chosen = 0x01
            self.console.log("[cyan]Plaintext chosen[/]")
        else:
            self.console.log("[red]Peer does not offer a supported encryption. Aborting.[/]")
            return None

        offset = 12
        # Read PadB_length(2 bytes)
        if len(buffer) < offset+2:
            needed = (offset+2)-len(buffer)
            extra = self.recv_exactly(s, needed)
            if not extra:
                self.console.log("[red]Could not read PadB_length[/]")
                return None
            buffer += extra

        PadB_length = int.from_bytes(buffer[offset:offset+2], 'big')
        offset += 2
        if PadB_length < 0 or PadB_length > 512:
            self.console.log("[red]Invalid PadB_length[/]")
            return None

        if len(buffer) < offset+PadB_length:
            needed = (offset+PadB_length)-len(buffer)
            extra = self.recv_exactly(s, needed)
            if not extra:
                self.console.log("[red]Could not read complete PadB[/]")
                return None
            buffer += extra
        PadB = buffer[offset:offset+PadB_length]
        offset += PadB_length

        # Read len(IA)(2bytes)
        if len(buffer) < offset+2:
            needed = (offset+2)-len(buffer)
            extra = self.recv_exactly(s, needed)
            if not extra:
                self.console.log("[red]Could not read len(IA)[/]")
                return None
            buffer += extra

        len_IA = int.from_bytes(buffer[offset:offset+2], 'big')
        offset += 2
        if len_IA < 0 or len_IA > 1024:
            self.console.log("[red]Invalid len_IA[/]")
            return None

        if len(buffer) < offset+len_IA:
            needed = (offset+len_IA)-len(buffer)
            extra = self.recv_exactly(s, needed)
            if not extra:
                self.console.log("[red]Could not read complete IA[/]")
                return None
            buffer += extra
        IA = buffer[offset:offset+len_IA]
        offset += len_IA

        if len(IA) >= 48 and IA[28:48] != info_hash:
            self.console.log("[red]info_hash in IA does not match[/]")
            return None

        # State D: Derive keys if RC4
        def sha1b(x): return hashlib.sha1(x).digest()
        keyA = sha1b(b'keyA' + S + SKEY)
        keyB = sha1b(b'keyB' + S + SKEY)

        rc4_in, rc4_out = None, None
        if chosen == 0x02:
            rc4_in = RC4State(keyB)
            rc4_out = RC4State(keyA)
            rc4_in.discard(1024)
            rc4_out.discard(1024)

        # Send the internal BT handshake
        VC = b'\x00'*8
        crypto_provide = b'\x00\x00\x00\x03'
        PadC_length = random.randint(0,512)
        PadC = os.urandom(PadC_length)

        protocol_name = b'BitTorrent protocol'
        reserved_bytes = b'\x00'*8
        bt_handshake = bytes([19]) + protocol_name + reserved_bytes + info_hash + self.peer_id
        len_IB = struct.pack(">H", len(bt_handshake))
        payload = VC + crypto_provide + PadC + len_IB + bt_handshake

        if chosen == 0x02:
            payload = rc4_out.crypt(payload)

        self.console.log("[cyan]Sending the encrypted internal BT handshake (State D)[/]")
        s.sendall(payload)
        self.console.log("[green]MSE handshake completed.[/]")

        return {
            'rc4_in': rc4_in,
            'rc4_out': rc4_out,
            'initial_bt_handshake': IA
        }
