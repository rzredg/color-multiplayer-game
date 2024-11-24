class NetworkingAPI {
    constructor(serverUrl) {
      this.serverUrl = serverUrl;
      this.socket = null;
      this.connectCallbacks = [];
      this.disconnectCallbacks = [];
      this.messageCallbacks = [];
      this.initSocket();
    }
  
    // Initialize WebSocket connection
    initSocket() {
      this.socket = new WebSocket(this.serverUrl);
  
      // WebSocket open event
      this.socket.addEventListener('open', () => {
        console.log('WebSocket connection established.');
        this.connectCallbacks.forEach((callback) => callback());
      });
  
      // WebSocket close event
      this.socket.addEventListener('close', () => {
        this.disconnectCallbacks.forEach((callback) => callback());
      });
  
      // WebSocket message event
      this.socket.addEventListener('message', (event) => {
        try {
            // Attempt to parse the message
            const message = JSON.parse(event.data);
            // Call all the message callback functions
            this.messageCallbacks.forEach((callback) => callback(message));
        } catch (e) {
            // If an error occurs during parsing, log it
            console.error('Error parsing message:', e, 'Message:', event.data);
        }
      });
    }
  
    // Register a callback for connection events
    onConnect(callback) {
      this.connectCallbacks.push(callback);
    }
  
    // Register a callback for disconnection events
    onDisconnect(callback) {
      this.disconnectCallbacks.push(callback);
    }
  
    // Register a callback for incoming messages
    onMessage(callback) {
      this.messageCallbacks.push(callback);
    }
  
    // Send a message to the server
    sendMessage(message) {
      if (this.socket && this.socket.readyState === WebSocket.OPEN) {
        this.socket.send(JSON.stringify(message));
      } else {
        console.error('WebSocket is not open.');
      }
    }
  }