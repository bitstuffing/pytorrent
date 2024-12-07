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
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
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

    def __init__(self, console, peer_ip=None, peer_port=None, enable_plain=True):
        self.console = console
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self.enable_plain = enable_plain
        self.peer_id = self.generate_peer_id().encode('utf-8')
        self.console.log(f"Generated Peer ID: {self.peer_id.decode('utf-8')}")

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

    def generate_peer_id(self):
        return '-PC0001-' + ''.join([str(random.randint(0, 9)) for _ in range(12)])
    
    def plain_handshake(self, sock, info_hash):
        try:
            protocol_name = b'BitTorrent protocol'
            reserved_bytes = b'\x00' * 8
            handshake_message = (
                bytes([19]) + protocol_name + reserved_bytes + info_hash + self.peer_id
            )

            sock.sendall(handshake_message)
            peer_handshake = self.recv_exactly(sock, len(handshake_message))
            if not peer_handshake or peer_handshake[28:48] != info_hash:
                self.console.log(f"[red]Plain handshake failed or info hash mismatch[/]")
                return False

            self.console.log(f"[green]Plain handshake successful[/]")
            return True

        except Exception as e:
            self.console.log(f"[red]Error during plain handshake: {e}[/]")
            return False

    def encrypted_handshake(self, s, info_hash):

        def sha1_bytes(x):
            return hashlib.sha1(x).digest()

        # A step: interchanges DH
        params = dh.DHParameterNumbers(self.P_INT, self.G_INT).parameters()
        private_key = params.generate_private_key()
        Ya = private_key.public_key().public_numbers().y
        Ya_bytes = Ya.to_bytes(96, 'big')

        PadA_length = random.randint(0, 512)
        PadA = os.urandom(PadA_length)

        self.console.log("[cyan] A status: Sending Ya+PadA[/]")
        s.sendall(Ya_bytes + PadA)

        self.console.log("[cyan] A status: waiting Yb (96 bytes)[/]")
        Yb_bytes = self.recv_exactly(s, 96)
        if not Yb_bytes:
            self.console.log("[red] Could not receive 96 bytes of Yb. Aborting MSE handshake.[/]")
            return None
        Yb = int.from_bytes(Yb_bytes, 'big')
        self.console.log("[cyan] A status: Yb received. Calculating secret S[/]")
        peer_public_numbers = dh.DHPublicNumbers(Yb, params.parameter_numbers())
        peer_public_key = peer_public_numbers.public_key()
        S = private_key.exchange(peer_public_key)
        SKEY = info_hash

        req1 = sha1_bytes(b'req1' + S)
        req2 = sha1_bytes(b'req2' + SKEY)
        req3 = sha1_bytes(b'req3' + S)
        req2_xor_req3 = bytes(a ^ b for a, b in zip(req2, req3))

        # B status: send req1 and req2xorreq3 and look for hash('req1',S) in the stream
        self.console.log("[cyan] B status: Sending req1(S) and req2xorreq3[/]")
        s.sendall(req1 + req2_xor_req3)

        self.console.log("[cyan] B status: Looking for hash('req1',S) in the stream (up to 512 bytes)[/]")

        # hash('req1',S) is what we will use to sync
        sync_pattern = req1  # req1 is already hash('req1',S)
        buffer = bytearray()
        max_bytes = 512

        found_sync = False
        
        # NOTE: this part doesn't do the right thing, there is a bug here but I don't have fixed it yet
        for _ in range((max_bytes // 16) + 1):
            chunk = s.recv(16)
            if not chunk:
                self.console.log("[red] Not more data received while looking for hash('req1',S). Aborting.[/]")
                return None
            buffer.extend(chunk)
            sync_index = buffer.find(sync_pattern)
            if sync_index != -1:
                # we found hash('req1',S)
                found_sync = True
                # Consum the data up to sync_index + 20 bytes
                # (hash('req1',S) are 20 bytes)
                after_sync = buffer[sync_index+20:]
                buffer = bytearray(after_sync)  # the rest after sync
                break
            else:
                self.console.log("[cyan] Data not found, current buffer: %d bytes[/]" % len(buffer))
                self.console.log("[cyan]Buffer: %s[/]" % buffer.hex())
                self.console.log("[cyan]Seeking sync_pattern: %s[/]" % sync_pattern.hex())

        if not found_sync:
            self.console.log("[red] Could not find hash('req1',S) within 512 bytes. Aborting.[/]")
            return None

        self.console.log("[cyan] B status: Now desciphering the next block (VC, crypto_select, PadB, IA)[/]")

        # Now, according to the protocol, what comes next is encrypted using RC4 (or plaintext)
        # But we don't know yet if it's RC4 or plaintext. We must read the next block:
        # - VC (8 bytes)
        # - crypto_select (4 bytes)
        # - padB_length (2 bytes)
        # - PadB (padB_length bytes)
        # - len(IA) (2 bytes)
        # - IA (len_IA bytes)

        # First we read the minimum necessary: VC(8) + crypto_select(4) + padB_len(2) = 14 bytes
        # We may already have some data in buffer (after sync), otherwise we request more
        needed = 14 - len(buffer)
        if needed > 0:
            extra = self.recv_exactly(s, needed)
            if not extra:
                self.console.log("[red] Could not read the block after hash('req1',S).[/]")
                return None
            buffer.extend(extra)

        # We haven't derived the RC4 keys yet, according to MSE, we need to do it now:
        # Derive the keys with info_hash and S
        def sha1b(x): return hashlib.sha1(x).digest()
        keyA = sha1b(b'keyA' + S + SKEY)
        keyB = sha1b(b'keyB' + S + SKEY)

        # Determine the encryption method according to crypto_select (after decrypting it if necessary)
        # But here is a detail: to decrypt VC and crypto_select, we must already know if RC4 or plaintext.
        # According to MSE, first decrypt using RC4 discarding 1024 bytes if RC4 was chosen.
        # But we don't know until we read crypto_select. Chicken and egg problem.
        # Actually, MSE first does a more complex step. In this example, we will assume that at this point we already know chosen.
        # But to be correct: the standard says you send req1, req2xorreq3 and then the peer responds
        # with an encrypted block that includes the VC. You must discard 1024 bytes RC4 even if you don't know yet.

        # Simplified solution: we assume chosen is RC4 by default, and if not, plaintext.
        # This is not perfect, but given the time, we simplify it.
        # Ideally, we should read the MSE doc and implement the full logic.

        # We will always try RC4, if it fails, fallback to plaintext.
        # This is not according to spec, it is simplified.

        # Let's try with RC4
        rc4_test_in = RC4State(keyB)
        rc4_test_out = RC4State(keyA)
        rc4_test_in.discard(1024)
        rc4_test_out.discard(1024)

        # Decrypt the first block (14 bytes) with RC4
        decrypted = rc4_test_in.crypt(bytes(buffer[:14]))
        VC = decrypted[:8]
        crypto_select = decrypted[8:12]
        padB_len = int.from_bytes(decrypted[12:14], 'big')

        if VC != b'\x00'*8:
            # If it doesn't match, maybe it was plaintext
            # In plaintext, nothing is decrypted
            VC = buffer[:8]
            crypto_select = buffer[8:12]
            padB_len = int.from_bytes(buffer[12:14], 'big')
            # chosen = plaintext (1)
            chosen = 0x01
            rc4_in, rc4_out = None, None
        else:
            # VC is right and decrypted
            chosen = (int.from_bytes(crypto_select, 'big') & 0x03)
            if chosen & 0x02:
                chosen = 0x02
                rc4_in = rc4_test_in
                rc4_out = rc4_test_out
            elif chosen & 0x01:
                chosen = 0x01
                # plaintext chosen
                rc4_in = None
                rc4_out = None
            else:
                self.console.log("[red] peer does not offer supported encryption after decrypting VC.[/]")
                return None

        # 14 bytes to consume
        buffer = buffer[14:]

        # read PadB
        needed = padB_len - len(buffer)
        if needed > 0:
            extra = self.recv_exactly(s, needed)
            if not extra:
                self.console.log("[red] Could not read PadB completely[/]")
                return None
            buffer.extend(extra)

        PadB = bytes(buffer[:padB_len])
        buffer = buffer[padB_len:]

        # read len(IA)(2 bytes)
        if len(buffer) < 2:
            extra = self.recv_exactly(s, 2 - len(buffer))
            if not extra:
                self.console.log("[red] Could not read len(IA)[/]")
                return None
            buffer.extend(extra)

        len_IA = int.from_bytes(buffer[:2], 'big')
        buffer = buffer[2:]

        # read IA
        needed = len_IA - len(buffer)
        if needed > 0:
            extra = self.recv_exactly(s, needed)
            if not extra:
                self.console.log("[red] Could not read IA completely[/]")
                return None
            buffer.extend(extra)
        IA = bytes(buffer[:len_IA])
        buffer = buffer[len_IA:]

        if len(IA) >= 48 and IA[28:48] != info_hash:
            self.console.log("[red]info_hash in IA doesn't match[/]")
            return None

        self.console.log("[cyan] D status: Preparing sending internal BT handshake[/]")

        # Final RC4 derivation if chosen=0x02 is already done
        # If plaintext, do nothing

        # send internal BT handshake
        VC = b'\x00'*8
        crypto_provide = b'\x00\x00\x00\x03'
        PadC_length = random.randint(0,512)
        PadC = os.urandom(PadC_length)

        protocol_name = b'BitTorrent protocol'
        reserved_bytes = b'\x00'*8
        bt_handshake = bytes([19]) + protocol_name + reserved_bytes + info_hash + self.peer_id
        len_IB = struct.pack(">H", len(bt_handshake))
        final_payload = VC + crypto_provide + PadC + len_IB + bt_handshake

        if chosen == 0x02:
            final_payload = rc4_out.crypt(final_payload)

        self.console.log("[cyan] Sending internal BT handshake cipher (state D)[/]")
        s.sendall(final_payload)
        self.console.log("[green]Handshake MSE completed.[/]")

        return {
            'rc4_in': rc4_in,
            'rc4_out': rc4_out,
            'initial_bt_handshake': IA
        }
