// Mock Erigon node for E2E testing
const express = require('express');
const app = express();
const PORT = process.env.PORT || 8545;

app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Mock JSON-RPC responses
const mockResponses = {
  'eth_call': {
    jsonrpc: '2.0',
    result: '0x0000000000000000000000000000000000000000000000000000000000000001',
    id: null,
  },
  'eth_getBalance': {
    jsonrpc: '2.0',
    result: '0x2386f26fc10000',
    id: null,
  },
  'eth_blockNumber': {
    jsonrpc: '2.0',
    result: '0x123456',
    id: null,
  },
};

app.post('/', (req, res) => {
  const { method, id } = req.body;
  
  console.log(`[Mock Node] Received request: ${method}`);
  
  const response = mockResponses[method] || {
    jsonrpc: '2.0',
    error: {
      code: -32601,
      message: `Method not found: ${method}`,
    },
    id: id || null,
  };
  
  response.id = id;
  
  res.json(response);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Mock Erigon node listening on port ${PORT}`);
});
