#!/usr/bin/env python
import socket
import mimetypes
from os import path
from datetime import datetime
from base64 import b64encode
from hashlib import sha1
from struct import pack, unpack

class HTTP:
	def run(self, options):
		isRunning = True
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server_socket.bind((options['host'], options['port']))
		server_socket.listen(options['max_connections'])

		while isRunning:
			self.client_socket, address = server_socket.accept()
			print '[Server] Incoming connection from {0}'.format(address)
			data = ''

			while True:
				stream_buffer = self.client_socket.recv(options['buffer_size'])
				end = stream_buffer.find("\r\n\r\n")
				if end != -1:
					data += stream_buffer[:end]
					break
				else:	
					data += stream_buffer

			request = self.parseRequest(data);
			self.routeRequest(request)
			self.client_socket.close()

	def parseRequest(self, raw_request):
		lines = raw_request.split('\r\n')
		status_line = lines.pop(0)
		method, path, protocol = status_line.split()
		headers = dict([line.split(': ') for line in lines])
		return {
			'method': method,
			'path': path,
			'protocol': protocol,
			'headers': headers
		}

	def routeRequest(self, request):
		if 'Upgrade' in request['headers'] and request['headers']['Upgrade'] == 'websocket':
			self.websocketHandshake(request)
		else:
			if request['path'] == '/':
				requested_path = '/index.html'
			else:
				requested_path = request['path']

			if path.exists('www_root'+requested_path):
				fileType, fileEncoding = mimetypes.guess_type('www_root'+requested_path)
				with open('www_root'+requested_path, 'r') as file:
					self.client_socket.sendall(self.createResponse(200, file.read(), {
						'Content-Type': fileType
					}))
			else:
				self.client_socket.sendall(self.createResponse(404))

	def websocketHandshake(self, request):
		UUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
		sec_key = b64encode(sha1(request['headers']['Sec-WebSocket-Key']+UUID).digest())
		response = self.createResponse(101, '', {
			'Upgrade': 'websocket',
			'Connection': request['headers']['Connection'],
			'Sec-WebSocket-Accept': sec_key,
			'Sec-WebSocket-Protocol': 'echo',
			'Sec-WebSocket-Version': 13
		})

		self.client_socket.sendall(response);
		self.wsEcho()

	def wsEcho(self):
		stream_connected = True
		frame = False
		while stream_connected:
			data = self.client_socket.recv(1024)
			if frame:
				if len(frame['payload']) < frame['size']:
					frame['payload'] += self.unmaskPayload(frame['mask'], data) if frame['mask'] else data
			else:	
				frame = self.parseFrame(data)

			if len(frame['payload']) == frame['size']:
				self.client_socket.sendall(self.createFrame(frame['payload']))
				frame = False

	def unmaskPayload(self, mask, payload):
		decoded = ''
		for _i, byte in enumerate(payload):
			decoded += chr(ord(byte) ^ ord(mask[_i % 4]))
		return decoded

	def parseFrame(self, data):
		c2b = lambda c: "{0:08b}".format(ord(c)) # Support converter
		
		### First Byte Section ####
		first_byte_flags = ['fin', 'rsv1', 'rsv2', 'rsv3']
		opt_codes =  {
			'0000': 'continuation',
			'0001': 'text',
			'0010': 'binary',
			'1000': 'close_connection',
			'1001': 'ping',
			'1010': 'pong'
		}
		first_byte = c2b(data[0])
		flags = dict(zip(first_byte_flags, list(first_byte[:4])))
		opcode = opt_codes[first_byte[4:]]
		
		### Second Byte Section ###
		second_byte = c2b(data[1])
		masked = second_byte[0]
		offset = 2 if masked else 0
		size = int(second_byte[1:], 2)
		
		if (size == 126):
			size = unpack('!H',data[2:4])[0]
			offset += 2 
		elif (size == 127):
			size = unpack('!Q',data[2:10])[0]
			offset += 8

		parsed_frame = {
			'flags': flags,
			'opcode': opcode
		}

		if size > 0:
			parsed_frame.update({
				'size': size,
				'mask': data[offset:offset+4] if masked else False,
				'payload': self.unmaskPayload(data[offset:offset+4], data[offset+4:]) if masked else data[offset:]
			})
		return parsed_frame

	def createFrame(self, payload):
		size = len(payload)
		header = chr(129) # Fin, Text Frame
		if size <= 125:
			header += pack("!B", size)
		elif size <= 65535 :
			header += chr(126) + pack("!H", size)
		else:
			header += chr(127) + pack("!Q", size)
		return header+payload

	def createResponse(self, code, body='', custom_headers={}):
		HTTPCodes = {
			200: 'OK',
			101: 'Switching Protocols',
			404: 'Not Found'
		}
		status = "HTTP/1.1 {code} {message}\r\n".format(**{
			'code': code,
			'message': HTTPCodes[code]
		})

		date_string = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
		server_name = 'Crusher'
		software = 'Python 2.7'
		content_length = len(body.encode('utf-8'))
		headers = {
			'Date': date_string,
			'Server': server_name,
			'X-Powered-By': software,
			'Last-Modified': date_string,
			'Content-Language': 'ru',
			'Content-Type': 'text/html; charset=utf-8',
			'Content-Length': str(content_length)
		}
		headers.update(custom_headers)
		raw_headers = status + '\r\n'.join((': '.join([key, str(headers[key])]) for key in list(headers))) + '\r\n\r\n'
		if body:
			raw_headers += body + '\r\n'
		return raw_headers

	def error(self, code):
		pass

def main():
	options = {
		'host': socket.gethostname(),
		'port': 8088,
		'buffer_size': 4096,
		'max_connections': 5
	}

	server = HTTP()
	server.run(options)

if __name__ == '__main__':
	main()