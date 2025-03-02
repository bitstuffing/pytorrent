import hashlib
import requests
import urllib.parse
import bencodepy
import socket
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
import os
from collections import defaultdict
import config
from concurrent.futures import ThreadPoolExecutor, as_completed
import struct
from datetime import datetime, timedelta
import sys
from urllib.parse import quote
import random
import json
from threading import Lock
from handshakehandler import HandshakeHandler, RC4State

sys.set_int_max_str_digits(10000)

class TorrentHandler(HandshakeHandler):
    def __init__(self, torrent_path):
        self.console = Console()
        super().__init__(self.console)
        self.block_buffer = defaultdict(lambda: {})
        self.trackers_url = "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt"
        
        self.console.print("[bold magenta]Parsing .torrent file...[/]")
        self.torrent_info = self.parse_torrent_file(torrent_path)
        self.total_pieces = len(self.torrent_info['pieces']) // 20  # each SHA1 hash has 20 bytes

        self.download_directory = os.path.join(config.DOWNLOAD_PATH, self.torrent_info['name'])
        if not os.path.exists(self.download_directory):
            os.makedirs(self.download_directory)

        # Progress tracking
        self.progress_file = os.path.join(self.download_directory, "download.progress")
        self.downloaded_pieces_lock = Lock()
        self.load_progress()
        self.downloaded_pieces = set()
        self.block_buffer = defaultdict(dict)
        self.block_buffer_lock = Lock()
        self.file_write_lock = Lock()

        self.load_progress()
        self.failed_peers = {}

    def print_download_status(self):
        with self.downloaded_pieces_lock:
            downloaded = len(self.downloaded_pieces)
            total = self.total_pieces
            progress = downloaded / total * 100 if total > 0 else 0
            speed = 0 # TODO: Calculate download speed

        table = Table(title="Download Status")
        table.add_column("Downloaded", style="cyan", justify="right")
        table.add_column("Total", style="magenta", justify="right")
        table.add_column("Progress", style="green", justify="right")
        table.add_column("Speed", style="yellow", justify="right")
        table.add_row(f"{downloaded} pieces", f"{total} pieces", f"{progress:.2f}%", f"{speed:.2f} KB/s")
        self.console.print(table)

    # Load progress from file if it exists
    def load_progress(self):
        if os.path.exists(self.progress_file):
            with open(self.progress_file, 'r') as f:
                progress_data = json.load(f)
                with self.downloaded_pieces_lock:
                    self.downloaded_pieces = set(progress_data.get('downloaded_pieces', []))
                self.console.print(f"[green]Progress loaded. Restarting download...[/]")
        else:
            with self.downloaded_pieces_lock:
                self.downloaded_pieces = set()


    # Save current progress to file
    def save_progress(self):
        with self.downloaded_pieces_lock:
            progress_data = {
                'downloaded_pieces': list(self.downloaded_pieces)
            }
        with open(self.progress_file, 'w') as f:
            json.dump(progress_data, f)
        self.console.print(f"[cyan]Progress stored.[/]")
        self.print_download_status()


    def parse_torrent_file(self, torrent_path):
        with open(torrent_path, 'rb') as f:
            torrent_data = bencodepy.decode(f.read())
        
        info = torrent_data[b'info']
        info_hash = hashlib.sha1(bencodepy.encode(info)).digest()
        announce_list = self.fetch_trackers(self.trackers_url)
        
        # Get the name from info dictionary
        name = info[b'name'].decode()  # Add this line

        if b'announce-list' in torrent_data:
            for tier in torrent_data[b'announce-list']:
                announce_list.extend([tracker.decode() for tracker in tier])
        elif b'announce' in torrent_data:
            announce_list.append(torrent_data[b'announce'].decode())

        pieces = info[b'pieces']
        piece_length = info[b'piece length']
        
        files = []
        if b'files' in info:
            for file in info[b'files']:
                files.append({
                    'path': b'/'.join(file[b'path']).decode(),
                    'length': file[b'length']
                })
        else:
            files.append({
                'path': info[b'name'].decode(),
                'length': info[b'length']
            })
        
        return {
            'announce_list': announce_list,
            'pieces': pieces,
            'piece_length': piece_length,
            'files': files,
            'info': info,  
            'info_hash': info_hash,
            'name': name,  # Add this line
            'length': sum(file['length'] for file in files)  # Total length
        }

    def fetch_trackers(self, url): 
        announce_list = []
        response = requests.get(url) 
        trackers = response.text.splitlines()
        for tracker in trackers: 
            announce_list.append(tracker)
        return announce_list

    def connect_to_tracker(self):
        info_hash = self.torrent_info['info_hash']
        left = sum(file['length'] for file in self.torrent_info['files'])
        peers = []

        with Progress() as progress:
            task = progress.add_task("[cyan] Connecting to trackers...", total=len(self.torrent_info['announce_list']))

            for announce_url in self.torrent_info['announce_list']:
                progress.update(task, description=f"[cyan]Trying to connect: {announce_url}[/]")
                try:
                    params = {
                        'port': '6881',
                        'uploaded': '0',
                        'downloaded': '0',
                        'left': str(left),
                        'compact': '1'
                    }
                    encoded_info_hash = self.percent_encode_bytes(info_hash)
                    encoded_peer_id = self.percent_encode_bytes(self.peer_id)
                    query_string = urllib.parse.urlencode(params)
                    full_url = f"{announce_url}?info_hash={encoded_info_hash}&peer_id={encoded_peer_id}&{query_string}"

                    self.console.log(f"Full URL: {full_url}")

                    response = requests.get(full_url, timeout=30)
                    if response.status_code == 200:
                        progress.update(task, advance=1)
                        self.console.log(f"[green] Connected successfully to tracker: {announce_url}[/]")
                        peers = self.parse_peers(response.content)
                        if not peers:
                            self.console.log("[yellow] Could not find any peers in tracker response.[/]")
                        break
                    else:
                        self.console.log(f"[red] Failed to connect to tracker {announce_url}. HTTP status code: {response.status_code}[/]")
                        progress.update(task, advance=1)

                except requests.exceptions.RequestException as e:
                    self.console.log(f"[red]Error to connect to tracker {announce_url}: {e}[/]")
                    progress.update(task, advance=1)

        if not peers:
            self.console.log("[red] Couldn't connect to any available tracker.")
        return peers

    def percent_encode_bytes(self, input_bytes):
        return quote(input_bytes, safe='')

    def parse_peers(self, response_content):
        response_dict = bencodepy.decode(response_content)
        peers = []
        if b'peers' in response_dict:
            peers_field = response_dict[b'peers']
            if isinstance(peers_field, list):
                for peer in peers_field:
                    ip = peer[b'ip'].decode('utf-8')
                    port = peer[b'port']
                    peers.append((ip, port))
            else:
                peers_binary = peers_field
                for i in range(0, len(peers_binary), 6):
                    ip = '.'.join(str(b) for b in peers_binary[i:i+4])
                    port = int.from_bytes(peers_binary[i+4:i+6], byteorder='big')
                    peers.append((ip, port))
        return peers

    def connect_to_peers(self, peers):
        # Check if download is already complete
        if self.is_download_complete():
            self.console.print("[green]Download is complete. No need to connect to more peers.[/]")
            return

        info_hash = self.torrent_info['info_hash']
        self.console.print(f"[cyan]Connecting to peers using workers...[/]")

        successful_peers = []

        # Separate peers into new and failed
        fresh_peers = [p for p in peers if p[0] not in self.failed_peers]
        failed_peers = [p for p in peers if p[0] in self.failed_peers]

        # Combine fresh peers first and then failed ones
        ordered_peers = fresh_peers + failed_peers

        def connect_peer(peer_ip, peer_port):
            if self.connect_to_peer(peer_ip, peer_port, info_hash):
                successful_peers.append((peer_ip, peer_port))

        with ThreadPoolExecutor(max_workers=config.MAX_WORKERS) as executor:
            futures = []
            for peer_ip, peer_port in ordered_peers:
                if self.is_download_complete():
                    break
                futures.append(executor.submit(connect_peer, peer_ip, peer_port))

            for future in as_completed(futures):
                future.result()  # This will raise any exception if the worker failed

        self.console.print(f"[green]Successfully connected to {len(successful_peers)} peers.[/]")

    """
    Establishes a connection to a peer
    """
    def connect_to_peer(self, peer_ip, peer_port, info_hash, retry_attempts=1):
        now = datetime.now()
        if peer_ip in self.failed_peers:
            next_retry_time = self.failed_peers[peer_ip]['next_retry']
            if now < next_retry_time:
                self.console.log(f"[yellow]Skipping connection to peer {peer_ip}:{peer_port} until {next_retry_time}[/]")
                return False

        for attempt in range(retry_attempts):
            try:
                self.console.log(f"[blue]Attempting connection to {peer_ip}:{peer_port} (Attempt {attempt + 1}/{retry_attempts})[/]")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((peer_ip, peer_port))

                result = None
                # try encrypted handshake first
                if config.ENABLE_ENCRYPTED:
                    result = self.encrypted_handshake(s, info_hash)
                    if result is not None:
                        # successful encrypted handshake
                        rc4_in = result['rc4_in']
                        rc4_out = result['rc4_out']
                        
                        self.console.log(f"[green]Successful encrypted handshake with peer {peer_ip}. Starting communication with peer.[/]")

                        # Start communication with peer using encrypted handshake
                        self.start_peer_communication(s, peer_ip, peer_port, info_hash, rc4_in, rc4_out)
                        return True
                if result is None or not config.ENABLE_ENCRYPTED:
                    self.console.log("[yellow]Peer does not support encrypted handshake. Retrying with plain handshake.[/]")
                    s.close()
                    if config.ENABLE_PLAIN: # TODO retry with plain handshake, now disabled to get working encrypted handshake
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(10)
                        s.connect((peer_ip, peer_port))
                        if self.plain_handshake(s, info_hash):
                            self.console.log("[green]Plain handshake successful. Starting communication with peer.[/]")
                            self.start_peer_communication(s, peer_ip, peer_port, info_hash, None, None)
                            return True
                        else:
                            self.console.log("[red]Peer does not support plain handshake. Jumping to next peer...[/]")
                            s.close()
                            return False

            except Exception as e:
                self.console.log(f"[red]Error connecting to peer {peer_ip}:{peer_port}: {e}[/]")

        # Mark this peer as failed and schedule next retry
        retry_count = self.failed_peers.get(peer_ip, {}).get('retry_count', 0) + 1
        retry_delay = min(5 * retry_count, 30)  # Incremental delay up to 30 minutes
        self.failed_peers[peer_ip] = {
            'next_retry': now + timedelta(minutes=retry_delay),
            'retry_count': retry_count
        }

        self.console.log(f"[red]Failed to connect to peer {peer_ip}:{peer_port} after {retry_attempts} attempts. Will retry in {retry_delay} minutes.[/]")
        return False
    
    def is_download_complete(self):
        with self.downloaded_pieces_lock:
            return len(self.downloaded_pieces) == self.total_pieces

    def recv_remaining_data(self, s):
        s.settimeout(10)
        data = b''
        try:
            while True:
                part = s.recv(4096)
                if not part:
                    break
                data += part
                if len(data) > 1024:
                    break
        except socket.timeout:
            pass
        return data

    """Simple RC4 implementation for MSE/PE"""
    def rc4_crypt(self, data, key):
        S = list(range(256))
        j = 0
        
        # KSA (Key Scheduling Algorithm)
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        # PRGA (Pseudo-Random Generation Algorithm)
        i = j = 0
        result = bytearray()
        
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)
            
        return bytes(result)

    """
    Handles communication with a peer after the handshake.
    If encryption_key is provided, encrypt/decrypt messages.
    """
    def start_peer_communication(self, socket, peer_ip, peer_port, info_hash, rc4_in=None, rc4_out=None):
        peer_state = {
            'socket': socket,
            'rc4_in': rc4_in,
            'rc4_out': rc4_out,
            'peer_choked': True,
            'peer_pieces': set(),
            'have_pieces': self.downloaded_pieces.copy(),
            'total_pieces': self.total_pieces,
            'requested_blocks': set(),
            'received_blocks': set(),
        }

        # Send interested message and start message exchange
        self.send_interested(socket, peer_state)
        self.listen_for_messages(socket, peer_ip, peer_port, peer_state)


    def recv_exactly(self, sock, num_bytes):
        buf = b''
        while len(buf) < num_bytes:
            try:
                #data = sock.recv(num_bytes - len(buf))
                # fragment it to avoid blocking
                data = sock.recv(min(4096, num_bytes - len(buf)))
                if not data:
                    return None
                buf += data
            except socket.error:
                return None
        return buf

    def send_message(self, s, message, peer_state):
        if peer_state['rc4_out']:
            rc4crypter = peer_state['rc4_out'] # Use RC4 to encrypt the message
            encrypted_message = rc4crypter.crypt(message)
            s.sendall(encrypted_message)
        else:
            s.sendall(message)

    def recv_message(self, s, num_bytes, peer_state):
        data = self.recv_exactly(s, num_bytes)
        if data and peer_state['rc4_in']:
            rc4crypter = peer_state['rc4_in'] # Use RC4 to decrypt the message
            decrypted_data = rc4crypter.crypt(data)
            return decrypted_data
        return data

    def send_interested(self, s, peer_state):
        interested_msg = b'\x00\x00\x00\x01\x02'
        self.send_message(s, interested_msg, peer_state)
        self.console.log(f"[blue]Sent 'interested' message to peer.[/]")

    def send_bitfield(self, s, peer_state):
        if not peer_state['have_pieces']:
            self.console.log("[yellow]We have no pieces to send in bitfield. Skipping sending bitfield.[/]")
            return  # Don't send bitfield if we have no pieces

        bitfield_length = (peer_state['total_pieces'] + 7) // 8
        bitfield = bytearray(bitfield_length)

        for piece_index in peer_state['have_pieces']:
            byte_index = piece_index // 8
            bit_index = 7 - (piece_index % 8)
            bitfield[byte_index] |= (1 << bit_index)

        bitfield_msg = struct.pack(">I", len(bitfield) + 1) + b'\x05' + bitfield
        try:
            self.send_message(s, bitfield_msg, peer_state)
            self.console.log(f"[blue]Sent bitfield message to peer.[/]")
        except Exception as e:
            self.console.log(f"[red]Failed to send bitfield message to peer: {e}[/]")

    def listen_for_messages(self, s, peer_ip, peer_port, peer_state):
        try:
            while True:
                s.settimeout(30)
                msg_length_bytes = self.recv_message(s, 4, peer_state)
                if msg_length_bytes is None:
                    self.console.log(f"[yellow]Connection closed by peer {peer_ip}:{peer_port} while reading message length. Closing connection.[/]")
                    break

                msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
                self.console.log(f"Received message length: {msg_length}")

                if msg_length == 0:
                    continue  # keep-alive message

                msg_id_bytes = self.recv_message(s, 1, peer_state)
                self.console.log(f"Received message ID: {msg_id_bytes[0]}")

                if msg_id_bytes is None:
                    self.console.log(f"[yellow]Connection closed by peer {peer_ip}:{peer_port} while reading message ID. Closing connection.[/]")
                    break

                msg_id = msg_id_bytes[0]
                payload_length = msg_length - 1

                # Initialize payload as an empty byte string, to ensure it has a value
                payload = b''

                if payload_length > 0:
                    payload = self.recv_message(s, payload_length, peer_state)
                    if payload is None:
                        self.console.log(f"[yellow]Connection closed by peer {peer_ip}:{peer_port} while reading payload. Closing connection.[/]")
                        break

                # handle the message according to the message ID
                self.handle_message(s, msg_id, payload, peer_ip, peer_port, peer_state)

        except socket.timeout:
            self.console.log(f"[yellow]Socket timeout while communicating with peer {peer_ip}:{peer_port}. Retrying...[/]")
        except Exception as e:
            self.console.log(f"[red]Error while communicating with peer {peer_ip}:{peer_port}: {e}[/]")
        finally:
            s.close()
            self.console.log(f"[blue]Connection with peer {peer_ip}:{peer_port} closed.[/]")

    def handle_message(self, s, msg_id, payload, peer_ip, peer_port, peer_state):
        if msg_id == 0:  # choke
            peer_state['peer_choked'] = True
        elif msg_id == 1:  # unchoke
            peer_state['peer_choked'] = False
            self.request_more_pieces(s, peer_state)
        elif msg_id == 4:  # have
            piece_index = struct.unpack('>I', payload)[0]
            peer_state['peer_pieces'].add(piece_index)
        elif msg_id == 5:  # bitfield
            bitfield = payload
            for i in range(len(bitfield)):
                byte = bitfield[i]
                for bit in range(8):
                    if byte & (1 << (7 - bit)):
                        piece_index = i * 8 + bit
                        if piece_index < self.total_pieces:
                            peer_state['peer_pieces'].add(piece_index)
        elif msg_id == 7:  # piece
            piece_index, offset = struct.unpack('>II', payload[:8])
            block = payload[8:]
            self.store_block(piece_index, offset, block, peer_state)
            # continue listening for more blocks
            self.request_more_pieces(s, peer_state)
        else:
            self.console.log(f"[yellow]Received unknown message ID: {msg_id}[/]")
        # TODO: Handle other message types here

    def store_block(self, piece_index, offset, block, peer_state):
        with self.block_buffer_lock:
            if piece_index not in self.block_buffer:
                self.block_buffer[piece_index] = {}
            self.block_buffer[piece_index][offset] = block
        peer_state['received_blocks'].add((piece_index, offset))

        # Check if we have received all blocks for this piece
        if len(self.block_buffer[piece_index]) == self.get_total_blocks(piece_index):
            self.verify_and_store_piece(piece_index, peer_state)

    def get_total_blocks(self, piece_index):
        piece_length = self.torrent_info['piece_length']
        total_length = self.torrent_info['length']
        last_piece_length = total_length % piece_length
        if piece_index == len(self.torrent_info['pieces']) // 20 - 1:
            return (last_piece_length + 2**14 - 1) // 2**14
        return (piece_length + 2**14 - 1) // 2**14

    def request_more_pieces(self, s, peer_state):
        if peer_state['peer_choked']:
            return

        block_size = 2**14  # 16 KiB
        piece_length = self.torrent_info['piece_length']

        with self.downloaded_pieces_lock:
            needed_pieces = peer_state['peer_pieces'] - self.downloaded_pieces - set(self.block_buffer.keys())

        if not needed_pieces:
            return

        piece_index = random.choice(list(needed_pieces))
        total_blocks = self.get_total_blocks(piece_index)
        for block_index in range(total_blocks):
            offset = block_index * block_size
            block_length = min(block_size, piece_length - offset)

            if (piece_index, offset) in peer_state['requested_blocks']:
                continue

            request_msg = struct.pack('>IBIII', 13, 6, piece_index, offset, block_length)
            try:
                self.send_message(s, request_msg, peer_state)
                peer_state['requested_blocks'].add((piece_index, offset))
            except Exception as e:
                self.console.log(f"[red]Error requesting block to peer: {e}[/]")
                break

    def listen_for_block_response(self, s, peer_state, piece_index, offset):
        try:
            s.settimeout(config.MAX_TIMEOUT_PER_CONNECTION)
            while True:
                msg_length_bytes = self.recv_message(s, 4, peer_state)
                if msg_length_bytes is None:
                    self.console.log(f"[yellow]Connection closed by peer while waiting for block response. Closing connection.[/]")
                    return

                #msg_length = int.from_bytes(msg_length_bytes, byteorder='big') # 2973387785 is so big, it's not possible to convert to int
                msg_length = struct.unpack('>I', msg_length_bytes)[0]
                if msg_length == 0:
                    continue

                msg_id_bytes = self.recv_message(s, 1, peer_state)
                if msg_id_bytes is None:
                    self.console.log(f"[yellow]Connection closed by peer while reading message ID. Closing connection.[/]")
                    return

                msg_id = msg_id_bytes[0]

                if msg_id == 7:  # 'piece' message
                    payload = self.recv_message(s, msg_length - 1, peer_state)
                    if payload is None:
                        self.console.log(f"[yellow]Connection closed by peer while reading payload. Closing connection.[/]")
                        return

                    index = int.from_bytes(payload[0:4], byteorder='big')
                    begin = int.from_bytes(payload[4:8], byteorder='big')
                    block = payload[8:]

                    if index == piece_index and begin == offset:
                        self.console.log(f"[green]Received block for piece {index}, offset {begin}.[/]")
                        self.store_block(index, begin, block, peer_state)
                        return
                else:
                    self.handle_message(s, msg_id, payload, "", "", peer_state)

        except socket.timeout:
            self.console.log(f"[yellow]Timeout while waiting for block response from peer.[/]")

    def verify_and_store_piece(self, piece_index, peer_state):
        with self.block_buffer_lock:
            piece_data = b''.join(self.block_buffer[piece_index][i] for i in sorted(self.block_buffer[piece_index]))
            del self.block_buffer[piece_index]

        # verify hash of piece
        expected_hash = self.torrent_info['pieces'][piece_index * 20:(piece_index + 1) * 20]
        sha1 = hashlib.sha1()
        sha1.update(piece_data)
        is_valid = expected_hash == sha1.digest()

        if is_valid:
            # write piece to file
            self.write_piece_to_file(piece_index, piece_data)
            with self.downloaded_pieces_lock:
                self.downloaded_pieces.add(piece_index)
            self.save_progress()
            self.console.print(f"[green]Piece {piece_index} downloaded and verified successfully.[/]")
        else:
            self.console.log(f"[red]Piece {piece_index} failed verification and will be re-downloaded.[/]")
            with self.downloaded_pieces_lock:
                self.downloaded_pieces.discard(piece_index)  # assure the piece is re-requested
            self.request_piece_again(piece_index, peer_state)  # request the piece again

    def request_piece_again(self, piece_index, peer_state):
        block_size = 2**14  # 16 KiB
        piece_length = self.torrent_info['piece_length']
        total_blocks = self.get_total_blocks(piece_index)

        for block_index in range(total_blocks):
            offset = block_index * block_size
            block_length = min(block_size, piece_length - offset)

            request_msg = struct.pack('>IBIII', 13, 6, piece_index, offset, block_length)
            try:
                self.send_message(peer_state['socket'], request_msg, peer_state)
                peer_state['requested_blocks'].add((piece_index, offset))
            except Exception as e:
                self.console.log(f"[red]Error requesting block to peer: {e}[/]")
                break

    def write_piece_to_file(self, piece_index, piece_data):
        output_file = os.path.join(self.download_directory, self.torrent_info['name'])
        with self.file_write_lock:
            with open(output_file, 'r+b') as f:
                piece_length = self.torrent_info['piece_length']
                f.seek(piece_index * piece_length)
                f.write(piece_data)

    def initialize_output_file(self):
        output_file = os.path.join(self.download_directory, self.torrent_info['name'])
        total_length = self.torrent_info['length']
        if not os.path.exists(output_file):
            with open(output_file, 'wb') as f:
                f.truncate(total_length)


if __name__ == "__main__":
    torrent_path = "example.torrent"
    handler = TorrentHandler(torrent_path)
    handler.initialize_output_file()
    peers = handler.connect_to_tracker()
    if peers:
        handler.connect_to_peers(peers)
