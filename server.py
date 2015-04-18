#!/usr/bin/env python
import socket
import mimetypes
from os import path
from datetime import datetime
from base64 import b64encode
from hashlib import sha1
from struct import pack


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
		c2b = lambda c: "{0:08b}".format(ord(c))
		stream_buffer = ''
		frame_size = 0
		while True:
			data = self.client_socket.recv(1024)

			if stream_buffer == '':
				print 'Start parsing frame...'
				first_byte = c2b(data[0])
				second_byte = c2b(data[1])
				masked = second_byte[0]

				if masked:
					print ' - this is masked frame'
					payload_offset = 2
				else:
					print ' - this isn\'t masked frame'
					payload_offset = 0
				
				size = int(second_byte[1:], 2)
				print 'Detecting payload size ' + second_byte[1:] 
				print ' - dec value is ' + str(size)
				
				if (size <= 125):
					print ' - using this size'
					real_size = size
				elif (size == 126):
					print ' - size in next 2 bytes ' + ''.join([c2b(c) for c in data[2:4]])
					real_size = int(''.join([c2b(c) for c in data[2:4]]), 2)
					print ' - detected size ' + str(real_size) + ' bytes'
					payload_offset += 2 
				elif (size == 127):
					print ' - size in next 8 bytes ' + ''.join([c2b(c) for c in data[2:10]])
					real_size = int(''.join([c2b(c) for c in data[2:10]]), 2)
					print ' - detected size ' + str(real_size) + ' bytes'
					payload_offset += 8

				if masked:
					mask = data[payload_offset:payload_offset+4]
					payload = data[payload_offset+4:]
				else:
					payload = data[payload_offset:]

				print 'Payload length ' + str(len(payload)) + ' bytes'

				if len(payload) < real_size:
					stream_buffer += payload
					print 'Load Next... ' + str(len(stream_buffer)) + ' of ' + str(real_size)

				if len(payload) == real_size:
					print 'Full frame'
					self.createFrame(self.unmaskPayload(mask, payload))

			else:
				stream_buffer += data
				print 'Load Next... ' + str(len(stream_buffer)) + ' of ' + str(real_size)
				if  len(stream_buffer) >= real_size:
					payload = stream_buffer[:real_size]
					print 'Full frame'
					stream_buffer = ''
					self.createFrame(self.unmaskPayload(mask, payload))

	def unmaskPayload(self, mask, payload):
		c2b = lambda c: "{0:08b}".format(ord(c))
		print 'Unmask Payload'
		print ' - mask is ' + ''.join([c2b(c) for c in mask])
		decoded = ''
		for _i, byte in enumerate(payload):
			decoded += chr(ord(byte) ^ ord(mask[_i % 4]))
		return decoded

	def createFrame(self, payload):
		size = len(payload)
		response = chr(int('10000001', 2))
		if size <= 125:
			response += pack("!B", size)
		elif len(payload) <= 65535 :
			response += chr(126)
			response += pack("!H", size)
		else:
			response += chr(127)
			response += pack("!Q", size)
		self.client_socket.sendall(response+payload)

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