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
import time
import sys
import threading
from urllib.parse import quote
import random
import json

sys.set_int_max_str_digits(10000)

class TorrentHandler:
    def __init__(self, torrent_path):
        self.console = Console()
        self.block_buffer = defaultdict(lambda: {})
        self.download_directory = config.DOWNLOAD_PATH
        self.trackers_url = "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt"
        self.peer_id = self.generate_peer_id().encode('utf-8')
        self.console.log(f"Generated Peer ID: {self.peer_id.decode('utf-8')}")
        
        self.console.print("[bold magenta]Parsing .torrent file...[/]")
        self.torrent_info = self.parse_torrent_file(torrent_path)
        self.total_pieces = len(self.torrent_info['pieces']) // 20  # Cada hash SHA1 tiene 20 bytes

        # Progress tracking
        self.progress_file = os.path.join(self.download_directory, "download.progress")
        self.load_progress()

    # Load progress from file if it exists
    def load_progress(self):
        if os.path.exists(self.progress_file):
            with open(self.progress_file, 'r') as f:
                progress_data = json.load(f)
                self.downloaded_pieces = set(progress_data.get('downloaded_pieces', []))
                self.block_buffer = defaultdict(
                    lambda: {},
                    {
                        int(k): {int(offset): bytes.fromhex(block) for offset, block in v.items()}
                        for k, v in progress_data.get('block_buffer', {}).items()
                    }
                )
        else:
            self.downloaded_pieces = set()


    # Save current progress to file
    def save_progress(self):
        progress_data = {
            'downloaded_pieces': list(self.downloaded_pieces),
            'block_buffer': {
                k: {offset: block.hex() for offset, block in v.items()}
                for k, v in self.block_buffer.items()
            }
        }
        with open(self.progress_file, 'w') as f:
            json.dump(progress_data, f)


    def parse_torrent_file(self, torrent_path):
        with open(torrent_path, 'rb') as f:
            torrent_data = bencodepy.decode(f.read())
        
        info = torrent_data[b'info']
        info_hash = hashlib.sha1(bencodepy.encode(info)).digest()
        announce_list = self.fetch_trackers(self.trackers_url)

        if b'announce-list' in torrent_data:
            for tier in torrent_data[b'announce-list']:
                announce_list.extend([tracker.decode() for tracker in tier])
        else:
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
            'info_hash': info_hash  
        }
    
    def generate_peer_id(self):
        return '-PC0001-' + ''.join([str(random.randint(0, 9)) for _ in range(12)])

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
        info_hash = self.torrent_info['info_hash']

        with ThreadPoolExecutor(max_workers=config.MAX_WORKERS) as executor:
            future_to_peer = {
                executor.submit(self.connect_to_peer, peer_ip, peer_port, info_hash): (peer_ip, peer_port)
                for peer_ip, peer_port in peers
            }

            successful_peers = [future.result() for future in as_completed(future_to_peer) if future.result()]

        self.console.print(f"[green]Successfully connected to {len(successful_peers)} peers.[/]")

    def connect_to_peer(self, peer_ip, peer_port, info_hash, retry_attempts=3):
        peer_state = {
            'peer_choked': True,
            'peer_pieces': set(),
            'have_pieces': set(),
            'total_pieces': self.total_pieces,
            'requested_blocks': set(),
            'received_blocks': set(),
        }
        for attempt in range(retry_attempts):
            try:
                self.console.log(f"[blue]Connecting to peer {peer_ip}:{peer_port}... (Attempt {attempt + 1}/{retry_attempts})[/]")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(20)
                s.connect((peer_ip, peer_port))

                # Handshake
                protocol_name = b'BitTorrent protocol'
                reserved_bytes = b'\x00' * 8
                handshake = (bytes([19]) + protocol_name + reserved_bytes + info_hash + self.peer_id)
                s.sendall(handshake)

                response = self.recv_exactly(s, 68)
                if response is None or len(response) != 68:
                    self.console.log(f"[red]Handshake failed with peer {peer_ip}:{peer_port}.[/]")
                    s.close()
                    continue

                if response[28:48] != info_hash:
                    self.console.log(f"[red]Info hash does not match from peer {peer_ip}:{peer_port}.[/]")
                    s.close()
                    continue

                self.console.log(f"[green]Successfully connected to peer {peer_ip}:{peer_port}[/]")

                # Send bitfield if we have pieces
                if peer_state['have_pieces']:
                    self.send_bitfield(s, peer_state)

                self.send_interested(s, peer_state)

                self.listen_for_messages(s, peer_ip, peer_port, peer_state)
                return True  # Success connection
            except (socket.timeout, ConnectionError) as e:
                self.console.log(f"[yellow]Socket timeout or connection error with peer {peer_ip}:{peer_port}: {e}[/]")
                s.close()
            except Exception as e:
                self.console.log(f"[red]Error connecting to peer {peer_ip}:{peer_port}: {e}[/]")
                s.close()
        self.console.log(f"[red]Failed to connect to peer {peer_ip}:{peer_port} after {retry_attempts} attempts.[/]")
        return False

    def recv_exactly(self, sock, num_bytes):
        data = b''
        while len(data) < num_bytes:
            packet = sock.recv(num_bytes - len(data))
            if not packet:
                # Socket closed by peer
                return None
            data += packet
        return data

    def send_interested(self, s, peer_state):
        interested_msg = b'\x00\x00\x00\x01\x02'
        s.sendall(interested_msg)
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
            s.sendall(bitfield_msg)
            self.console.log(f"[blue]Sent bitfield message to peer.[/]")
        except Exception as e:
            self.console.log(f"[red]Failed to send bitfield message to peer: {e}[/]")

    def listen_for_messages(self, s, peer_ip, peer_port, peer_state):
        try:
            while True:
                s.settimeout(30)
                msg_length_bytes = self.recv_exactly(s, 4)
                if msg_length_bytes is None:
                    self.console.log(f"[yellow]Connection closed by peer {peer_ip}:{peer_port} while reading message length. Closing connection.[/]")
                    break

                msg_length = int.from_bytes(msg_length_bytes, byteorder='big')

                if msg_length == 0:
                    continue  # keep-alive message

                msg_id_bytes = self.recv_exactly(s, 1)
                if msg_id_bytes is None:
                    self.console.log(f"[yellow]Connection closed by peer {peer_ip}:{peer_port} while reading message ID. Closing connection.[/]")
                    break

                msg_id = msg_id_bytes[0]
                payload_length = msg_length - 1

                # Initialize payload as an empty byte string, to ensure it has a value
                payload = b''

                if payload_length > 0:
                    payload = self.recv_exactly(s, payload_length)
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
        if msg_id == 0:  # Choke
            self.console.log(f"[yellow]Received 'choke' from peer {peer_ip}:{peer_port}.[/]")
            peer_state['peer_choked'] = True
        elif msg_id == 1:  # Unchoke
            self.console.log(f"[green]Received 'unchoke' from peer {peer_ip}:{peer_port}.[/]")
            peer_state['peer_choked'] = False
            # Send requests for pieces if we are interested
            self.request_more_pieces(s, peer_state)
        elif msg_id == 2:  # Interested
            self.console.log(f"[blue]Peer {peer_ip}:{peer_port} is interested in our pieces.[/]")
        elif msg_id == 3:  # Not interested
            self.console.log(f"[yellow]Peer {peer_ip}:{peer_port} is not interested in our pieces.[/]")
        elif msg_id == 4:  # Have
            piece_index = int.from_bytes(payload, byteorder='big')
            self.console.log(f"[blue]Peer {peer_ip}:{peer_port} has piece {piece_index}.[/]")
            peer_state['peer_pieces'].add(piece_index)
        elif msg_id == 5:  # Bitfield
            self.console.log(f"[blue]Received 'bitfield' from peer {peer_ip}:{peer_port}.[/]")
            for i, byte in enumerate(payload):
                for bit in range(8):
                    if byte & (1 << (7 - bit)):
                        piece_index = (i * 8) + bit
                        if piece_index < peer_state['total_pieces']:
                            peer_state['peer_pieces'].add(piece_index)
        elif msg_id == 6:  # Request
            self.console.log(f"[blue]Received 'request' from peer {peer_ip}:{peer_port}. Ignoring as we are not uploading.[/]")
        elif msg_id == 7:  # Piece
            index = int.from_bytes(payload[0:4], byteorder='big')
            begin = int.from_bytes(payload[4:8], byteorder='big')
            block = payload[8:]
            self.console.log(f"[green]Received block for piece {index}, offset {begin} from peer {peer_ip}:{peer_port}.[/]")
            self.store_block(index, begin, block, peer_state)
        elif msg_id == 8:  # Cancel
            self.console.log(f"[yellow]Received 'cancel' from peer {peer_ip}:{peer_port}. Ignoring as we are not uploading.[/]")
        elif msg_id == 9:  # Port (DHT)
            self.console.log(f"[yellow]Received 'port' message for DHT from peer {peer_ip}:{peer_port}. Ignoring.[/]")
        else:
            self.console.log(f"[red]Received unknown message ID {msg_id} from peer {peer_ip}:{peer_port}.[/]")

    def store_block(self, piece_index, offset, block, peer_state):
        if piece_index not in self.block_buffer:
            self.block_buffer[piece_index] = {}

        # Store the block in the buffer
        self.block_buffer[piece_index][offset] = block
        peer_state['received_blocks'].add((piece_index, offset))

        # Update console with block received
        self.console.log(f"[green]Stored block for piece {piece_index}, offset {offset}. Blocks received: {len(self.block_buffer[piece_index])}/{self.get_total_blocks(piece_index)}[/]")

        # Check if the entire piece has been received
        if len(self.block_buffer[piece_index]) == self.get_total_blocks(piece_index):
            self.verify_and_store_piece(piece_index, peer_state)

        # Save progress to file
        self.save_progress()

        if piece_index not in self.block_buffer:
            self.block_buffer[piece_index] = {}

        self.block_buffer[piece_index][offset] = block
        peer_state['received_blocks'].add((piece_index, offset))

        # Verify if we have received all blocks for the piece
        piece_length = self.torrent_info['piece_length']
        total_blocks = (piece_length + len(block) - 1) // len(block)

        if len(self.block_buffer[piece_index]) == total_blocks:
            # Concat all blocks to form the complete piece
            piece_data = b''.join(self.block_buffer[piece_index][i * len(block)] for i in range(total_blocks))

            # Verify the piece using the SHA-1 hash
            expected_hash = self.torrent_info['pieces'][piece_index * 20:(piece_index + 1) * 20]
            actual_hash = hashlib.sha1(piece_data).digest()

            if actual_hash == expected_hash:
                self.console.log(f"[green]Successfully downloaded and verified piece {piece_index}.[/]")
                self.write_piece_to_file(piece_index, piece_data)
                peer_state['have_pieces'].add(piece_index)
            else:
                self.console.log(f"[red]Hash mismatch for piece {piece_index}. Discarding corrupted piece.[/]")
            
            # remove the piece from the buffer (when it's used)
            del self.block_buffer[piece_index]

    def get_total_blocks(self, piece_index):
        # Calculate the total number of blocks for a given piece
        piece_length = self.torrent_info['piece_length']
        block_size = 2**14  # 16 KiB
        if piece_index == self.total_pieces - 1:
            # The last piece may be smaller than the others
            total_length = sum(file['length'] for file in self.torrent_info['files'])
            last_piece_length = total_length - (piece_index * piece_length)
            return (last_piece_length + block_size - 1) // block_size
        else:
            return (piece_length + block_size - 1) // block_size

    def request_more_pieces(self, s, peer_state):
        if peer_state['peer_choked']:
            self.console.log(f"[yellow]Peer is choked. Cannot request more pieces at this moment.[/]")
            return

        block_size = 2**14  # 16 KiB

        for piece_index in peer_state['peer_pieces']:
            if piece_index in peer_state['have_pieces']:
                continue

            piece_length = self.torrent_info['piece_length']
            total_blocks = (piece_length + block_size - 1) // block_size

            for block_index in range(total_blocks):
                offset = block_index * block_size
                length = min(block_size, piece_length - offset)

                if (piece_index, offset) in peer_state['requested_blocks']:
                    continue

                peer_state['requested_blocks'].add((piece_index, offset))

                request_msg = struct.pack(">IBIII", 13, 6, piece_index, offset, length)
                try:
                    s.sendall(request_msg)
                    self.console.log(f"[cyan]Sent request for piece {piece_index}, offset {offset}, length {length}[/]")
                except Exception as e:
                    self.console.log(f"[red]Failed to send request for piece {piece_index}, offset {offset}: {e}[/]")
                    return

                self.listen_for_block_response(s, peer_state, piece_index, offset)

                if peer_state['peer_choked']:
                    self.console.log(f"[yellow]Peer choked us. Stopping further requests for now.[/]")
                    return

            if len(self.block_buffer[piece_index]) == total_blocks:
                self.verify_and_store_piece(piece_index, peer_state)

    def listen_for_block_response(self, s, peer_state, piece_index, offset):
        try:
            s.settimeout(30)
            while True:
                msg_length_bytes = self.recv_exactly(s, 4)
                if msg_length_bytes is None:
                    self.console.log(f"[yellow]Connection closed by peer while waiting for block response. Closing connection.[/]")
                    return

                msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
                if msg_length == 0:
                    continue

                msg_id_bytes = self.recv_exactly(s, 1)
                if msg_id_bytes is None:
                    self.console.log(f"[yellow]Connection closed by peer while reading message ID. Closing connection.[/]")
                    return

                msg_id = msg_id_bytes[0]

                if msg_id == 7:  # 'piece' message
                    payload = self.recv_exactly(s, msg_length - 1)
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
        piece_length = self.torrent_info['piece_length']
        total_blocks = self.get_total_blocks(piece_index)

        # Concatenate all blocks to form the complete piece
        piece_data = b''.join(self.block_buffer[piece_index][i * (2**14)] for i in range(total_blocks))

        # Verify the integrity of the piece using SHA1
        expected_hash = self.torrent_info['pieces'][piece_index * 20:(piece_index + 1) * 20]
        actual_hash = hashlib.sha1(piece_data).digest()

        if actual_hash == expected_hash:
            self.console.log(f"[green]Successfully downloaded and verified piece {piece_index}.[/]")
            self.write_piece_to_file(piece_index, piece_data)
            peer_state['have_pieces'].add(piece_index)
            self.downloaded_pieces.add(piece_index)
        else:
            self.console.log(f"[red]Hash mismatch for piece {piece_index}. Discarding corrupted piece.[/]")

        # Remove the buffer for the processed piece
        del self.block_buffer[piece_index]

        # Save progress to file
        self.save_progress()


    # Write the piece data to the output file
    def write_piece_to_file(self, piece_index, piece_data):
        piece_length = self.torrent_info['piece_length']
        offset_in_piece = 0

        for file_info in self.torrent_info['files']:
            # Calculate the path for the output file
            file_path = os.path.join(self.download_directory, file_info['path'])

            # Ensure that the directory structure exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Calculate file bounds in terms of torrent piece indices
            file_start = offset_in_piece
            file_end = file_start + file_info['length']

            # Determine the intersection of the current piece with the current file
            piece_start = piece_index * piece_length
            piece_end = piece_start + len(piece_data)

            intersect_start = max(file_start, piece_start)
            intersect_end = min(file_end, piece_end)

            if intersect_start < intersect_end:  # There is an overlap
                file_offset = intersect_start - file_start
                piece_offset = intersect_start - piece_start
                write_length = intersect_end - intersect_start

                # Open the file in read/write mode, creating it if necessary
                with open(file_path, "r+b" if os.path.exists(file_path) else "wb") as f:
                    f.seek(file_offset)
                    f.write(piece_data[piece_offset:piece_offset + write_length])

            offset_in_piece += file_info['length']



if __name__ == "__main__":
    torrent_path = "example.torrent"
    handler = TorrentHandler(torrent_path)
    peers = handler.connect_to_tracker()
    if peers:
        handler.connect_to_peers(peers)
