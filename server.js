import { findNumbersInString } from '@yext/phonenumber-util';
import { findTimeFromAreaCode, findRegionFromRegionCode } from '@yext/phonenumber-util/geo';
import { fileURLToPath } from 'url';
import http from 'http';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const LISTEN_PORT = 8080;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SAFE_ROOT_DIR = __dirname; // Restrict file serving to this directory

const OPCODES = {
  TEXT: 0x1,
  CLOSE: 0x8,
};

const activeSockets = new Set();

// Create an HTTP server
const server = http.createServer((req, res) => {
  /**
   * Handles HTTP requests and serves static files or responds with errors.
   * @param {http.IncomingMessage} req - The HTTP request object.
   * @param {http.ServerResponse} res - The HTTP response object.
   */
  if (req.method === 'GET') {
    if (req.url === '/') {
      serveFile(res, 'index.html');
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found\n');
    }
  } else {
    res.writeHead(405, { 'Content-Type': 'text/plain' });
    res.end('405 Method Not Allowed\n');
  }
});

server.on('connection', (socket) => {
  activeSockets.add(socket);

  socket.on('close', () => {
    activeSockets.delete(socket);
  });
});

// Handle WebSocket upgrades
server.on('upgrade', (req, socket, head) => {
  /**
   * Handles WebSocket upgrade requests and establishes the WebSocket connection.
   * @param {http.IncomingMessage} req - The HTTP request object.
   * @param {net.Socket} socket - The network socket between the server and client.
   * @param {Buffer} head - The first packet of the upgraded stream.
   */
  const key = req.headers['sec-websocket-key'];
  if (!key || Buffer.from(key, 'base64').length !== 16) {
    socket.destroy();
    return;
  }

  const acceptKey = generateAcceptKey(key);
  const responseHeaders = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${acceptKey}`,
  ];
  socket.write(responseHeaders.join('\r\n') + '\r\n\r\n');

  socket.on('data', (buffer) => {
    /**
     * Processes incoming WebSocket data and sends responses.
     * @param {Buffer} buffer - The raw WebSocket frame received from the client.
     */
    try {
      const message = parseMessage(buffer);
      console.log('Decoded message:', message);

      const response = constructMessage(parser(message));
      socket.write(response);
    } catch (error) {
      console.error('WebSocket error:', error.message);

      const closeFrame = constructCloseFrame(1002, 'Protocol error');
      socket.write(closeFrame);
      socket.end();
    }
  });

  socket.on('close', () => {
    /**
     * Handles the WebSocket connection close event.
     */
    console.log('WebSocket connection closed');
  });

  socket.on('error', (err) => {
    /**
     * Handles errors on the WebSocket connection.
     * @param {Error} err - The error object.
     */
    if (err.code === 'EPIPE') {
      console.error('Socket write error: EPIPE - client likely disconnected');
    } else {
      console.error('Socket error:', err);
    }
  });
});

/**
 * Serves a static file to the client.
 * Ensures the requested file is within the safe root directory.
 * @param {http.ServerResponse} res - The HTTP response object.
 * @param {string} filePath - The path to the file to be served.
 */
function serveFile(res, filePath) {
  const safePath = path.resolve(SAFE_ROOT_DIR, filePath);

  if (!safePath.startsWith(SAFE_ROOT_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('403 Forbidden\n');
    return;
  }

  const ext = path.extname(safePath).toLowerCase();

  fs.readFile(safePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found\n');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('500 Internal Server Error\n');
      }
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(content);
    }
  });
}

/**
 * Constructs a WebSocket close frame.
 * @param {number} code - The WebSocket close code.
 * @param {string} reason - The reason for closing the connection.
 * @returns {Buffer} The WebSocket close frame.
 */
function constructCloseFrame(code, reason) {
  if (typeof code !== 'number' || code < 1000 || code > 4999) {
    throw new Error('Invalid WebSocket close code. Must be between 1000 and 4999.');
  }

  if (typeof reason !== 'string' || reason.length > 123) {
    throw new Error('Invalid WebSocket close reason. Must be a string with a maximum of 123 characters.');
  }

  const reasonBuffer = Buffer.from(reason);
  const frame = Buffer.alloc(2 + reasonBuffer.length);
  frame[0] = 0x88; // FIN + Close frame opcode
  frame[1] = reasonBuffer.length + 2; // Payload length
  frame.writeUInt16BE(code, 2); // Write close code
  reasonBuffer.copy(frame, 4); // Write reason
  return frame;
}

/**
 * Generates a Sec-WebSocket-Accept key for the WebSocket handshake.
 * @param {string} key - The Sec-WebSocket-Key sent by the client.
 * @returns {string} The Sec-WebSocket-Accept key.
 */
function generateAcceptKey(key) {
  const magicString = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
  return crypto.createHash('sha1').update(key + magicString).digest('base64');
}

/**
 * Parses a WebSocket frame and extracts the message.
 * @param {Buffer} buffer - The raw WebSocket frame received from the client.
 * @returns {string} The decoded message.
 * @throws Will throw an error if the frame is incomplete or invalid.
 */
function parseMessage(buffer) {
  const firstByte = buffer[0];
  const opcode = firstByte & 0b00001111; // Extract opcode
  const secondByte = buffer[1];
  const isMasked = (secondByte & 0b10000000) !== 0; // Check if frame is masked
  let payloadLength = secondByte & 0b01111111; // Initial payload length (7 bits)
  let maskStart = 2;

  if (payloadLength === 126) {
    payloadLength = buffer.readUInt16BE(2);
    maskStart = 4;
  } else if (payloadLength === 127) {
    const highBits = buffer.readUInt32BE(2);
    const lowBits = buffer.readUInt32BE(6);

    if (highBits !== 0) {
      throw new Error('Payload length too large to handle (> 2^32 - 1)');
    }
    payloadLength = lowBits;
    maskStart = 10;
  }

  const dataStart = isMasked ? maskStart + 4 : maskStart;

  if (buffer.length < dataStart + payloadLength) {
    throw new Error('Incomplete frame received');
  }

  const mask = isMasked ? buffer.slice(maskStart, maskStart + 4) : null;
  const data = buffer.slice(dataStart, dataStart + payloadLength);

  const unmasked = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) {
    unmasked[i] = isMasked ? data[i] ^ mask[i % 4] : data[i];
  }

  if (!isValidUTF8(unmasked)) {
    throw new Error('Invalid UTF-8 in text frame');
  }

  return unmasked.toString('utf8', 0, payloadLength);
}

/**
 * Validates if a given buffer contains valid UTF-8 encoded data.
 * @param {Buffer} buffer - The buffer to validate as UTF-8.
 * @returns {boolean} True if the buffer contains valid UTF-8, false otherwise.
 */
function isValidUTF8(buffer) {
  try {
    const text = buffer.toString('utf8');
    return Buffer.from(text, 'utf8').equals(buffer);
  } catch {
    return false;
  }
}

/**
 * Constructs a WebSocket frame from a message.
 * @param {string} message - The message to send to the client.
 * @returns {Buffer} The WebSocket frame.
 */
function constructMessage(message) {
  const messageBuffer = Buffer.from(message);
  const frame = [];

  frame.push(0x81); // FIN + text frame
  if (messageBuffer.length < 126) {
    frame.push(messageBuffer.length);
  } else if (messageBuffer.length < 65536) {
    frame.push(126);
    frame.push((messageBuffer.length >> 8) & 0xff);
    frame.push(messageBuffer.length & 0xff);
  } else {
    frame.push(127);
    frame.push(0, 0, 0, 0);
    frame.push((messageBuffer.length >> 24) & 0xff);
    frame.push((messageBuffer.length >> 16) & 0xff);
    frame.push((messageBuffer.length >> 8) & 0xff);
    frame.push(messageBuffer.length & 0xff);
  }

  return Buffer.concat([Buffer.from(frame), messageBuffer]);
}

/**
 * Processes a client message and generates a reply.
 * @param {string} message - The message received from the client.
 * @returns {string} The processed message to send back to the client.
 */
function parser(message) {
  const numbers = findNumbersInString(message);
  const goodNumbers = numbers.map((item) => {
    if (item.areaCode) {
      const geo = findTimeFromAreaCode(item.areaCode);
      return { ...item, ...geo };
    } else {
      const geo = findRegionFromRegionCode(item.regionCode);
      return { ...item, ...geo };
    }
  });

  return JSON.stringify(goodNumbers, null, 2);
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  /**
   * Handles server shutdown on interrupt signal (e.g., Ctrl+C).
   */
  console.log('Shutting down server...');

  // Close the server
  server.close(() => {
    console.log('Server closed');

    // Destroy remaining active sockets
    activeSockets.forEach((socket) => socket.destroy());
    process.exit(0);
  });

  // If shutdown hangs, forcefully destroy all active sockets
  setTimeout(() => {
    console.log('Forcing shutdown due to hanging sockets...');
    activeSockets.forEach((socket) => socket.destroy());
    process.exit(1);
  }, 3000); // 3 seconds timeout
});

// Start the server
server.listen(LISTEN_PORT, () => {
  /**
   * Logs that the server has started and is listening for connections.
   */
  console.log('WebSocket server running on ws://localhost:' + LISTEN_PORT);
});
