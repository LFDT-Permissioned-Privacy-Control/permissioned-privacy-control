import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { TestRequestPanel } from '../TestRequestPanel';

// Shape of the JSON body the panel POSTs to /api/v1/admin/test-request.
// params is heterogeneous (e.g. [{ to, data }, 'latest']) so its elements
// are typed as unknown and narrowed at the individual assertion sites.
interface TestRequestBody {
  method?: string;
  params?: unknown[];
  jwt_token?: string;
}

function setupEthPriceHandlers(price: number = 2500) {
  server.use(
    http.get('/api/v1/admin/orgs', () => {
      return HttpResponse.json({
        data: [{ id: 'org-1', slug: 'test', name: 'Test Org', settings: {}, created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T00:00:00Z' }],
        total: 1, limit: 1, offset: 0,
      });
    }),
    http.get('/api/v1/admin/orgs/:orgId/compliance/tokens', () => {
      return HttpResponse.json({
        data: [{ id: 'tp-1', org_id: 'org-1', token_address: 'native', symbol: 'ETH', decimals: 18, price_fiat: price, created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T00:00:00Z' }],
      });
    }),
  );
}

function setupSuccessHandler(handler?: (body: TestRequestBody) => void) {
  server.use(
    http.post('/api/v1/admin/test-request', async ({ request }) => {
      const body = (await request.json()) as TestRequestBody;
      handler?.(body);
      return HttpResponse.json({
        result: '0x1234',
        latency_ms: 42,
        identity: 'test:dashboard',
      });
    })
  );
}

function setupForbiddenHandler() {
  server.use(
    http.post('/api/v1/admin/test-request', () => {
      return HttpResponse.json(
        { error: 'access denied', identity: 'test:dashboard' },
        { status: 403 }
      );
    })
  );
}

describe('TestRequestPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Rendering', () => {
    it('renders the card with title "Test Request"', () => {
      render(<TestRequestPanel />);

      expect(screen.getByText('Test Request')).toBeInTheDocument();
    });

    it('renders the method dropdown with default "eth_blockNumber"', () => {
      render(<TestRequestPanel />);

      const trigger = screen.getByRole('combobox');
      expect(trigger).toHaveTextContent('eth_blockNumber');
    });

    it('renders the Send button', () => {
      render(<TestRequestPanel />);

      expect(screen.getByRole('button', { name: /send/i })).toBeInTheDocument();
    });

    it('shows params textarea by default (RPC method selected)', () => {
      render(<TestRequestPanel />);

      expect(screen.getByText('Params (JSON array, optional)')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('["0x...", "latest"]')).toBeInTheDocument();
    });

    it('does not show contract address field by default', () => {
      render(<TestRequestPanel />);

      expect(screen.queryByText('Contract Address')).not.toBeInTheDocument();
    });
  });

  describe('Method selection', () => {
    it('can select an RPC method (e.g. eth_getBalance)', async () => {
      const user = userEvent.setup();
      render(<TestRequestPanel />);

      const trigger = screen.getByRole('combobox');
      await user.click(trigger);

      const option = await screen.findByRole('option', { name: 'eth_getBalance' });
      await user.click(option);

      expect(trigger).toHaveTextContent('eth_getBalance');
    });

    it('selecting an ERC20 method shows contract address input', async () => {
      const user = userEvent.setup();
      render(<TestRequestPanel />);

      const trigger = screen.getByRole('combobox');
      await user.click(trigger);

      const option = await screen.findByRole('option', { name: 'ERC20 - balanceOf' });
      await user.click(option);

      expect(screen.getByText('Contract Address')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('0x...')).toBeInTheDocument();
    });

    it('selecting ERC20 - balanceOf shows owner address field', async () => {
      const user = userEvent.setup();
      render(<TestRequestPanel />);

      const trigger = screen.getByRole('combobox');
      await user.click(trigger);

      const option = await screen.findByRole('option', { name: 'ERC20 - balanceOf' });
      await user.click(option);

      expect(screen.getByText('Owner')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Owner address (0x...)')).toBeInTheDocument();
    });

    it('selecting ERC20 - totalSupply shows contract address but no extra fields', async () => {
      const user = userEvent.setup();
      render(<TestRequestPanel />);

      const trigger = screen.getByRole('combobox');
      await user.click(trigger);

      const option = await screen.findByRole('option', { name: 'ERC20 - totalSupply' });
      await user.click(option);

      expect(screen.getByText('Contract Address')).toBeInTheDocument();
      // totalSupply has no fields beyond contract address
      expect(screen.queryByText('Owner')).not.toBeInTheDocument();
      expect(screen.queryByText('Spender')).not.toBeInTheDocument();
      expect(screen.queryByText('Recipient')).not.toBeInTheDocument();
      expect(screen.queryByText('Amount')).not.toBeInTheDocument();
    });

    it('selecting ERC20 - allowance shows owner and spender fields', async () => {
      const user = userEvent.setup();
      render(<TestRequestPanel />);

      const trigger = screen.getByRole('combobox');
      await user.click(trigger);

      const option = await screen.findByRole('option', { name: 'ERC20 - allowance' });
      await user.click(option);

      expect(screen.getByText('Contract Address')).toBeInTheDocument();
      expect(screen.getByText('Owner')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Owner address (0x...)')).toBeInTheDocument();
      expect(screen.getByText('Spender')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Spender address (0x...)')).toBeInTheDocument();
    });

    it('selecting ERC20 - transfer shows recipient and amount fields', async () => {
      const user = userEvent.setup();
      render(<TestRequestPanel />);

      const trigger = screen.getByRole('combobox');
      await user.click(trigger);

      const option = await screen.findByRole('option', { name: 'ERC20 - transfer' });
      await user.click(option);

      expect(screen.getByText('Contract Address')).toBeInTheDocument();
      expect(screen.getByText('Recipient')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Recipient address (0x...)')).toBeInTheDocument();
      // Amount label includes (uint256) suffix
      expect(screen.getByText(/Amount/)).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Amount (in wei)')).toBeInTheDocument();
    });

    it('switching from ERC20 back to RPC method hides contract fields, shows params textarea', async () => {
      const user = userEvent.setup();
      render(<TestRequestPanel />);

      // First select ERC20 method
      const trigger = screen.getByRole('combobox');
      await user.click(trigger);
      const erc20Option = await screen.findByRole('option', { name: 'ERC20 - balanceOf' });
      await user.click(erc20Option);

      // Verify ERC20 fields are shown
      expect(screen.getByText('Contract Address')).toBeInTheDocument();
      expect(screen.queryByText('Params (JSON array, optional)')).not.toBeInTheDocument();

      // Switch back to RPC method
      await user.click(trigger);
      const rpcOption = await screen.findByRole('option', { name: 'eth_chainId' });
      await user.click(rpcOption);

      // Verify contract fields are hidden and params textarea is back
      expect(screen.queryByText('Contract Address')).not.toBeInTheDocument();
      expect(screen.getByText('Params (JSON array, optional)')).toBeInTheDocument();
    });
  });

  describe('Advanced section', () => {
    it('JWT token section is hidden by default', () => {
      render(<TestRequestPanel />);

      expect(screen.queryByText('JWT Token')).not.toBeInTheDocument();
      expect(
        screen.queryByPlaceholderText('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...')
      ).not.toBeInTheDocument();
    });

    it('clicking "Advanced: Test with JWT Token" reveals JWT input', async () => {
      const user = userEvent.setup();
      render(<TestRequestPanel />);

      const advancedButton = screen.getByText('Advanced: Test with JWT Token');
      await user.click(advancedButton);

      expect(screen.getByText('JWT Token')).toBeInTheDocument();
      expect(
        screen.getByPlaceholderText('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...')
      ).toBeInTheDocument();
    });

    it('shows descriptive help text about JWT', async () => {
      const user = userEvent.setup();
      render(<TestRequestPanel />);

      const advancedButton = screen.getByText('Advanced: Test with JWT Token');
      await user.click(advancedButton);

      expect(
        screen.getByText(
          'Paste a JWT token to test as a specific user identity. Copy from the user dashboard after authentication.'
        )
      ).toBeInTheDocument();
    });
  });

  describe('Form submission - RPC methods', () => {
    it('sends request with default method and empty params', async () => {
      const user = userEvent.setup();
      let capturedBody: TestRequestBody | undefined;
      setupSuccessHandler((body) => {
        capturedBody = body;
      });

      render(<TestRequestPanel />);

      const sendButton = screen.getByRole('button', { name: /send/i });
      await user.click(sendButton);

      await waitFor(() => expect(capturedBody).toBeDefined());
      expect(capturedBody?.method).toBe('eth_blockNumber');
      expect(capturedBody?.params).toEqual([]);
    });

    it('sends request with custom JSON params', async () => {
      const user = userEvent.setup();
      let capturedBody: TestRequestBody | undefined;
      setupSuccessHandler((body) => {
        capturedBody = body;
      });

      render(<TestRequestPanel />);

      // Select eth_getBalance which takes params
      const trigger = screen.getByRole('combobox');
      await user.click(trigger);
      const option = await screen.findByRole('option', { name: 'eth_getBalance' });
      await user.click(option);

      // Enter params (use click + paste to avoid userEvent interpreting [ and " as special keys)
      const paramsTextarea = screen.getByPlaceholderText('["0x...", "latest"]');
      await user.click(paramsTextarea);
      await user.paste('["0x1234567890123456789012345678901234567890", "latest"]');

      const sendButton = screen.getByRole('button', { name: /send/i });
      await user.click(sendButton);

      await waitFor(() => expect(capturedBody).toBeDefined());
      expect(capturedBody?.method).toBe('eth_getBalance');
      expect(capturedBody?.params).toEqual([
        '0x1234567890123456789012345678901234567890',
        'latest',
      ]);
    });

    it('shows 200 OK badge and result on success', async () => {
      const user = userEvent.setup();
      setupSuccessHandler();

      render(<TestRequestPanel />);

      const sendButton = screen.getByRole('button', { name: /send/i });
      await user.click(sendButton);

      await waitFor(() => {
        expect(screen.getByText('200 OK')).toBeInTheDocument();
      });

      // Result should be displayed
      expect(screen.getByText('"0x1234"')).toBeInTheDocument();
      // Latency displayed
      expect(screen.getByText('42ms')).toBeInTheDocument();
      // Identity displayed
      expect(screen.getByText(/Identity: test:dashboard/)).toBeInTheDocument();
    });

    it('shows 403 FORBIDDEN badge on access denied', async () => {
      const user = userEvent.setup();
      setupForbiddenHandler();

      render(<TestRequestPanel />);

      const sendButton = screen.getByRole('button', { name: /send/i });
      await user.click(sendButton);

      await waitFor(() => {
        expect(screen.getByText('403 FORBIDDEN')).toBeInTheDocument();
      });

      // Error message should be displayed
      expect(screen.getByText('access denied')).toBeInTheDocument();
    });

    it('shows error for invalid JSON params (SyntaxError)', async () => {
      const user = userEvent.setup();
      render(<TestRequestPanel />);

      // Use click + paste to avoid userEvent interpreting { and } as special keys
      const paramsTextarea = screen.getByPlaceholderText('["0x...", "latest"]');
      await user.click(paramsTextarea);
      await user.paste('{invalid json}');

      const sendButton = screen.getByRole('button', { name: /send/i });
      await user.click(sendButton);

      await waitFor(() => {
        expect(screen.getByText('Invalid JSON in params')).toBeInTheDocument();
      });
    });
  });

  describe('Form submission - ERC20 methods', () => {
    it('sends eth_call with encoded balanceOf calldata', async () => {
      const user = userEvent.setup();
      let capturedBody: TestRequestBody | undefined;
      setupSuccessHandler((body) => {
        capturedBody = body;
      });

      render(<TestRequestPanel />);

      // Select balanceOf
      const trigger = screen.getByRole('combobox');
      await user.click(trigger);
      const option = await screen.findByRole('option', { name: 'ERC20 - balanceOf' });
      await user.click(option);

      // Fill contract address
      const contractInput = screen.getByPlaceholderText('0x...');
      await user.type(contractInput, '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48');

      // Fill owner address
      const ownerInput = screen.getByPlaceholderText('Owner address (0x...)');
      await user.type(ownerInput, '0x1234567890123456789012345678901234567890');

      const sendButton = screen.getByRole('button', { name: /send/i });
      await user.click(sendButton);

      await waitFor(() => expect(capturedBody).toBeDefined());
      expect(capturedBody?.method).toBe('eth_call');
      const callArg = capturedBody?.params?.[0] as { to?: string; data?: string };
      expect(callArg.to).toBe(
        '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
      );
      expect(callArg.data).toBe(
        '0x70a082310000000000000000000000001234567890123456789012345678901234567890'
      );
      expect(capturedBody?.params?.[1]).toBe('latest');
    });

    it('shows validation error when contract address is empty', async () => {
      const user = userEvent.setup();
      render(<TestRequestPanel />);

      // Select balanceOf
      const trigger = screen.getByRole('combobox');
      await user.click(trigger);
      const option = await screen.findByRole('option', { name: 'ERC20 - balanceOf' });
      await user.click(option);

      // Don't fill contract address, just click send
      const sendButton = screen.getByRole('button', { name: /send/i });
      await user.click(sendButton);

      await waitFor(() => {
        expect(screen.getByText('Contract address is required')).toBeInTheDocument();
      });
    });

    it('shows validation error when required field (owner) is empty', async () => {
      const user = userEvent.setup();
      render(<TestRequestPanel />);

      // Select balanceOf
      const trigger = screen.getByRole('combobox');
      await user.click(trigger);
      const option = await screen.findByRole('option', { name: 'ERC20 - balanceOf' });
      await user.click(option);

      // Fill contract address but leave owner empty
      const contractInput = screen.getByPlaceholderText('0x...');
      await user.type(contractInput, '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48');

      const sendButton = screen.getByRole('button', { name: /send/i });
      await user.click(sendButton);

      await waitFor(() => {
        expect(screen.getByText('owner is required')).toBeInTheDocument();
      });
    });

    it('sends eth_call with encoded allowance calldata (two address params)', async () => {
      const user = userEvent.setup();
      let capturedBody: TestRequestBody | undefined;
      setupSuccessHandler((body) => {
        capturedBody = body;
      });

      render(<TestRequestPanel />);

      // Select allowance
      const trigger = screen.getByRole('combobox');
      await user.click(trigger);
      const option = await screen.findByRole('option', { name: 'ERC20 - allowance' });
      await user.click(option);

      // Fill contract address
      const contractInput = screen.getByPlaceholderText('0x...');
      await user.type(contractInput, '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48');

      // Fill owner
      const ownerInput = screen.getByPlaceholderText('Owner address (0x...)');
      await user.type(ownerInput, '0xAAAABBBBCCCCDDDDEEEEFFFF0000111122223333');

      // Fill spender
      const spenderInput = screen.getByPlaceholderText('Spender address (0x...)');
      await user.type(spenderInput, '0x4444555566667777888899990000AAAABBBBCCCC');

      const sendButton = screen.getByRole('button', { name: /send/i });
      await user.click(sendButton);

      await waitFor(() => expect(capturedBody).toBeDefined());
      expect(capturedBody?.method).toBe('eth_call');
      const callArg = capturedBody?.params?.[0] as { to?: string; data?: string };
      expect(callArg.to).toBe(
        '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
      );
      // dd62ed3e + owner padded + spender padded
      const expectedData =
        '0xdd62ed3e' +
        '000000000000000000000000aaaabbbbccccddddeeeeffff0000111122223333' +
        '0000000000000000000000004444555566667777888899990000aaaabbbbcccc';
      expect(callArg.data).toBe(expectedData);
      expect(capturedBody?.params?.[1]).toBe('latest');
    });
  });

  describe('JWT token', () => {
    it('sends jwt_token in request when provided', async () => {
      const user = userEvent.setup();
      let capturedBody: TestRequestBody | undefined;
      setupSuccessHandler((body) => {
        capturedBody = body;
      });

      render(<TestRequestPanel />);

      // Open advanced section
      const advancedButton = screen.getByText('Advanced: Test with JWT Token');
      await user.click(advancedButton);

      // Enter JWT token
      const jwtInput = screen.getByPlaceholderText(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
      );
      await user.type(jwtInput, 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig');

      // Send request
      const sendButton = screen.getByRole('button', { name: /send/i });
      await user.click(sendButton);

      await waitFor(() => expect(capturedBody).toBeDefined());
      expect(capturedBody?.jwt_token).toBe(
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig'
      );
    });
  });

  describe('USD display for eth_sendTransaction', () => {
    it('shows USD equivalent when ETH amount is entered', async () => {
      const user = userEvent.setup();
      setupEthPriceHandlers(2000);
      setupSuccessHandler();

      render(<TestRequestPanel />);

      // Select eth_sendTransaction
      const trigger = screen.getByRole('combobox');
      await user.click(trigger);
      const option = await screen.findByRole('option', { name: 'eth_sendTransaction' });
      await user.click(option);

      // Enter amount in the ETH field
      const amountInput = screen.getByPlaceholderText('0.1');
      await user.type(amountInput, '1.5');

      // Wait for USD equivalent to appear
      await waitFor(() => {
        expect(screen.getByText(/\$3,000\.00 USD/)).toBeInTheDocument();
      });

      expect(screen.getByText(/\$2,000\.00\/ETH/)).toBeInTheDocument();
    });

    it('shows wei hex conversion', async () => {
      const user = userEvent.setup();
      setupEthPriceHandlers(2000);
      setupSuccessHandler();

      render(<TestRequestPanel />);

      // Select eth_sendTransaction
      const trigger = screen.getByRole('combobox');
      await user.click(trigger);
      const option = await screen.findByRole('option', { name: 'eth_sendTransaction' });
      await user.click(option);

      // Enter amount
      const amountInput = screen.getByPlaceholderText('0.1');
      await user.type(amountInput, '1');

      // Check for wei text
      await waitFor(() => {
        expect(screen.getByText(/wei/)).toBeInTheDocument();
      });
    });

    it('does not show USD when price fetch fails', async () => {
      const user = userEvent.setup();
      // Override orgs handler to return error so ETH price fetch fails
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ error: 'Unauthorized' }, { status: 401 });
        }),
      );
      setupSuccessHandler();

      render(<TestRequestPanel />);

      // Select eth_sendTransaction
      const trigger = screen.getByRole('combobox');
      await user.click(trigger);
      const option = await screen.findByRole('option', { name: 'eth_sendTransaction' });
      await user.click(option);

      // Enter amount
      const amountInput = screen.getByPlaceholderText('0.1');
      await user.type(amountInput, '1');

      // Wei should still show
      await waitFor(() => {
        expect(screen.getByText(/wei/)).toBeInTheDocument();
      });

      // USD text should NOT appear
      expect(screen.queryByText(/USD/)).toBeNull();
    });
  });
});
