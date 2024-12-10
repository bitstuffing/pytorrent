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

            # First encrypt and send our message
            VC = b'\x00' * 8
            crypto_provide = struct.pack(">I", 2)  # Only offer RC4 (0x02)
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

            # Now receive and decrypt peer's message
            # First, search for encrypted VC pattern
            rc4_test = RC4State(keyB)
            rc4_test.discard(1024)
            
            test_vc = rc4_test.crypt(b'\x00' * 8)  # Use temporary RC4 state for pattern
            self.console.log(f"[cyan]Looking for VC pattern: {test_vc.hex()}")

            # Read initial chunk to search for pattern
            initial_data = self.recv_exactly(s, 96)  # Read a larger initial chunk
            if not initial_data:
                raise RuntimeError("Connection closed")

            search_buffer = bytearray(initial_data)
            pattern_pos = -1

            # Search in initial data
            for i in range(len(search_buffer) - 7):
                if search_buffer[i:i+8] == test_vc:
                    pattern_pos = i
                    break

            # If not found, keep reading until we find it or hit limit
            while pattern_pos == -1 and len(search_buffer) < 616:
                chunk = s.recv(1)
                if not chunk:
                    raise RuntimeError("Connection closed while searching for VC")
                search_buffer.extend(chunk)
                
                if len(search_buffer) >= 8:
                    for i in range(max(0, len(search_buffer) - 8 - 1), len(search_buffer) - 7):
                        if search_buffer[i:i+8] == test_vc:
                            pattern_pos = i
                            break

            if pattern_pos == -1:
                raise RuntimeError("Could not find VC pattern")

            self.console.log(f"[green]Found VC pattern at position {pattern_pos}!")

            # Recreate RC4 state and catch up to current position
            rc4_in = RC4State(keyB)
            rc4_in.discard(1024)
            if pattern_pos > 0:
                rc4_in.crypt(bytes(pattern_pos))  # Discard bytes before pattern

            # Read complete message: VC(8) + crypto_select(4) + len(PadD)(2)
            header = search_buffer[pattern_pos:pattern_pos+14]
            if len(header) < 14:
                # Read remaining header bytes if needed
                header += self.recv_exactly(s, 14 - len(header))

            decrypted = rc4_in.crypt(header)
            VC_recv = decrypted[:8]
            crypto_select = decrypted[8:12]
            PadD_len = int.from_bytes(decrypted[12:14], 'big')

            self.console.log(f"[cyan]crypto_select: {crypto_select.hex()}")
            self.console.log(f"[cyan]PadD length: {PadD_len}")

            # Read and decrypt PadD
            PadD = self.recv_exactly(s, PadD_len)
            if PadD:
                rc4_in.crypt(PadD)  # Discard PadD

            # Read and decrypt IB length (2 bytes)
            IB_len_bytes = rc4_in.crypt(self.recv_exactly(s, 2))
            IB_len = int.from_bytes(IB_len_bytes, 'big')
            self.console.log(f"[cyan]IB length: {IB_len}")

            # Read and decrypt IB
            IB_data = self.recv_exactly(s, IB_len)
            self.console.log("[cyan]Received encrypted IB")
            self.console.log(f"[cyan]Received encrypted IB: {IB_data.hex()}")
            if not IB_data or len(IB_data) != IB_len:
                raise RuntimeError(f"Failed to read complete IB (got {len(IB_data) if IB_data else 0} of {IB_len} bytes)")

            IB = rc4_in.crypt(IB_data)
            
            # Verify info_hash in IB
            if len(IB) < 48:
                self.console.log(f"[red]IB too short: {len(IB)} bytes")
                raise RuntimeError("IB message too short")

            received_hash = IB[28:48]
            self.console.log(f"[cyan]Protocol: {IB[1:20]}")
            self.console.log(f"[cyan]Expected hash: {info_hash.hex()}")
            self.console.log(f"[cyan]Received hash: {received_hash.hex()}")

            if received_hash != info_hash:
                raise RuntimeError("info_hash in IB does not match")

            self.console.log("[green]MSE handshake completed![/]")

            return {
                'rc4_in': rc4_in,
                'rc4_out': rc4_out,
                'initial_bt_handshake': IA, # IA is what we sent
                'peer_bt_handshake': IB    # IB is what we received
            }

        except Exception as e:
            self.console.log(f"[red]Error during encrypted handshake: {e}[/]")
            self.console.log(f"[red]Debug: Exception details: {str(e)}")
            return None
