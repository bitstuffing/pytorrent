import random
import hashlib
import os
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
            data = s.recv(num_bytes - len(buf))
            if not data:
                return None
            buf += data
        return buf

    def generate_peer_id(self):
        return '-PC0001-' + ''.join([str(random.randint(0, 9)) for _ in range(12)])
    
    def sha1_bytes(self, x):
        return hashlib.sha1(x).digest()

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
        try:
            # === Step 1: Send Ya + PadA ===
            params = dh.DHParameterNumbers(self.P_INT, self.G_INT).parameters()
            private_key = params.generate_private_key()
            Ya = private_key.public_key().public_numbers().y
            Ya_bytes = Ya.to_bytes(96, 'big')
            
            PadA_length = random.randint(0, 512)
            PadA = os.urandom(PadA_length)
            self.console.log("[cyan]A status: Sending Ya+PadA[/]")
            s.sendall(Ya_bytes + PadA)

            # === Step 2: Receive Yb + PadB ===
            self.console.log("[cyan]A status: Waiting for Yb (96 bytes)[/]")
            Yb_bytes = self.recv_exactly(s, 96)
            if not Yb_bytes:
                raise RuntimeError("Failed to receive Yb")
            Yb = int.from_bytes(Yb_bytes, 'big')

            # Calculate shared secret S (it's already bytes)
            peer_public_numbers = dh.DHPublicNumbers(Yb, params.parameter_numbers())
            peer_public_key = peer_public_numbers.public_key()
            S = private_key.exchange(peer_public_key)  # S is already bytes
            
            # === Step 3: Calculate and send req1, req2⊕req3 ===
            req1 = self.sha1_bytes(b'req1' + S)        # Use S directly, it's already bytes
            req2 = self.sha1_bytes(b'req2' + info_hash)
            req3 = self.sha1_bytes(b'req3' + S)        # Use S directly, it's already bytes
            req2_xor_req3 = bytes(a ^ b for a, b in zip(req2, req3))

            self.console.log("[cyan]C status: Sent req1 and req2xorreq3[/]")
            s.sendall(req1 + req2_xor_req3)

            # Derive RC4 keys using S (already bytes)
            keyA = self.sha1_bytes(b'keyA' + S + info_hash)
            keyB = self.sha1_bytes(b'keyB' + S + info_hash)

            self.console.log("[cyan]Debug: Using RC4 keys:")
            self.console.log(f"[cyan]keyA: {keyA.hex()}")
            self.console.log(f"[cyan]keyB: {keyB.hex()}")

            rc4_out = RC4State(keyA)
            rc4_in = RC4State(keyB)
            
            rc4_out.discard(1024)
            rc4_in.discard(1024)

            # === 4) Send ENCRYPT(VC, crypto_provide, PadC, IA)
            VC = b'\x00' * 8
            # we offer RC4 (0x02). (NOTE: study if it could be in a future 0x03 to offer plaintext + RC4)
            crypto_provide = struct.pack(">I", 0x02)
            PadC_length = random.randint(0, 512)
            PadC = os.urandom(PadC_length)
            
            protocol_name = b'BitTorrent protocol'
            reserved_bytes = b'\x00' * 8
            bt_handshake = bytes([19]) + protocol_name + reserved_bytes + info_hash + self.peer_id
            IA = bt_handshake

            message = (
                VC +
                crypto_provide +
                struct.pack(">H", PadC_length) +
                PadC +
                struct.pack(">H", len(IA)) +
                IA
            )

            encrypted_message = rc4_out.crypt(message)
            self.console.log(f"[cyan]Sending encrypted message len={len(encrypted_message)}")
            s.sendall(encrypted_message)

            # === 5) Receive ENCRYPT(VC, crypto_select, PadD, IB)
            # First, search for encrypted VC pattern; read 14 bytes: VC(8), crypto_select(4), len(PadD)(2)
            header = self.recv_exactly(s, 14)
            if not header:
                raise RuntimeError("No data for VC/crypto_select/PadD_len")

            decrypted_header = rc4_in.crypt(header)
            VC_recv = decrypted_header[:8]
            crypto_select = decrypted_header[8:12]
            PadD_len = int.from_bytes(decrypted_header[12:14], 'big')

            # verify VC
            if VC_recv != b'\x00'*8:
                raise RuntimeError("VC mismatch after decrypt")

            # verify if it's offered RC4 or plaintext
            chosen = int.from_bytes(crypto_select, 'big') & 0x03
            if chosen & 0x02:
                # continue with RC4
                self.console.log("[green]Peer chose RC4 encryption[/]")
            elif chosen & 0x01:
                # Plaintext chosen
                self.console.log("[yellow]Peer chose Plaintext. Disabling RC4 from now on.[/]")
                rc4_in = None
                rc4_out = None
            else:
                raise RuntimeError("No supported encryption method offered")

            # --- check PadD length ---
            MAX_PADD_LEN = 2048  # or 512, I think it could be 512
            if PadD_len > MAX_PADD_LEN:
                self.console.log(f"[yellow]PadD length is {PadD_len}, which is over our max {MAX_PADD_LEN} -> fallback to plain handshake[/]")
                
                return None

            # if PadD_len is good, continue
            PadD_data = self.recv_exactly(s, PadD_len)
            if not PadD_data:
                raise RuntimeError("Failed to read PadD data")
            if rc4_in:
                rc4_in.crypt(PadD_data)  # unencrypt and discart

            # read len(IB)
            IB_len_data = self.recv_exactly(s, 2)
            if not IB_len_data:
                raise RuntimeError("Failed to read IB length")
            if rc4_in:
                IB_len_data = rc4_in.crypt(IB_len_data)
            IB_len = int.from_bytes(IB_len_data, 'big')

            # read IB
            IB_data = self.recv_exactly(s, IB_len)
            if not IB_data or len(IB_data) < IB_len:
                raise RuntimeError("Failed to read IB fully")
            if rc4_in:
                IB = rc4_in.crypt(IB_data)
            else:
                IB = IB_data

            if len(IB) < 48 or IB[28:48] != info_hash:
                raise RuntimeError("info_hash in IB does not match")

            self.console.log("[green]MSE handshake completed successfully![/]")
            return {
                'rc4_in': rc4_in,
                'rc4_out': rc4_out,
                'initial_bt_handshake': IA,
                'peer_bt_handshake': IB,
                'fallback_used': False
            }

        except Exception as e:
            self.console.log(f"[red]Error during encrypted handshake: {e}[/]")
            return None
