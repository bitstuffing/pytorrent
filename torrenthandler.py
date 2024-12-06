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
        self.total_pieces = len(self.torrent_info['pieces']) // 20  # SHA-1 hashes are 20 bytes long

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
        max_workers = 10
        info_hash = self.torrent_info['info_hash']

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
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

if __name__ == "__main__":
    torrent_path = "example.torrent"
    handler = TorrentHandler(torrent_path)
    peers = handler.connect_to_tracker()
    if peers:
        handler.connect_to_peers(peers)
