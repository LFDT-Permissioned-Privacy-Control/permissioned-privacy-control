# Demo Video Generator

Automated demo video generation system for Open Privacy Suite. Creates promotional videos with narration, captions, and branding from YAML configuration files.

## Quick Start

```bash
# Initial setup (run once)
make demo-setup

# List available demos
make demo-list

# Generate a demo video
make demo name=auth-flow
```

## Requirements

### System Dependencies

- **Python 3.11+** with virtual environment support
- **Node.js 18+** for Playwright
- **FFmpeg** with ffprobe for video processing
- **Chrome/Chromium** installed (Playwright will manage this)

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | Yes (for TTS) | OpenAI API key for text-to-speech narration |
| `ANTHROPIC_API_KEY` | No | Anthropic API key for social media copy generation |
| `MOCK_SIGNATURES` | Yes (for demo) | Set to `true` to skip wallet signature verification (backend) |

### Running Services

For demo recording to work, the full application stack must be running with mock mode enabled:

1. **Backend server** - The Go proxy server with database (with `MOCK_SIGNATURES=true`)
2. **Frontend** - React development server (auto-started by Playwright)

```bash
# Terminal 1: Start backend with mock mode for demo recording
MOCK_SIGNATURES=true make run

# Terminal 2: Generate demo
make demo name=auth-flow
```

**Note:** `MOCK_SIGNATURES=true` is required because the Playwright mock wallet cannot produce cryptographically valid signatures. This setting is blocked in production environments.

## Architecture

```
demos/
├── configs/           # YAML demo configurations
├── src/
│   ├── config/        # Config loader and models
│   ├── recorder/      # Playwright spec generation and runner
│   ├── processors/    # TTS, captions, FFmpeg composition
│   ├── generators/    # Copy generation for social media
│   ├── clippers/      # Scene detection and clip extraction
│   └── exporters/     # Platform-specific exports (16:9, 9:16, 1:1)
├── playwright/        # Playwright tests and helpers
├── assets/            # Branding (logo, intro/outro videos)
└── output/            # Generated videos (gitignored)
```

## Commands

| Command | Description |
|---------|-------------|
| `make demo-setup` | Install Python venv and Playwright |
| `make demo-list` | List available demo configurations |
| `make demo name=<name>` | Generate complete demo with all assets |
| `make demo-record name=<name>` | Record video only |
| `make demo-process name=<name>` | Process existing recording |
| `make demo-clip video=<path>` | Extract clips from video |
| `make demo-all` | Generate all configured demos |
| `make demo-clean` | Clean generated outputs |

## Configuration

Demo configurations are YAML files in `configs/`. Example:

```yaml
version: "1"

metadata:
  name: "auth-flow"
  title: "Privacy-First Authentication"
  description: "ZK proof login without revealing identity"

video:
  resolution: { width: 1920, height: 1080 }
  fps: 60
  viewport: { width: 1280, height: 720 }

voice:
  provider: "openai"
  voice_id: "alloy"  # alloy, echo, fable, onyx, nova, shimmer
  speed: 1.0

steps:
  - id: "intro"
    action: "navigate"
    url: "/login"
    wait: { selector: "h1", timeout: 10000 }
    narration: "Welcome to Open Privacy Suite..."
    pause: 2.0
    screenshot: true

  - id: "click_button"
    action: "click"
    selector: "button:has-text('Login')"
    wait: { navigation: "/dashboard" }
    narration: "Click to log in..."

branding:
  watermark:
    position: "bottom-right"
    opacity: 0.7

export:
  - { aspect: "16:9", resolution: "1920x1080" }
  - { aspect: "9:16", resolution: "1080x1920", suffix: "-vertical" }
```

## Available Steps

| Action | Parameters | Description |
|--------|------------|-------------|
| `navigate` | `url` | Navigate to URL |
| `click` | `selector` | Click element |
| `fill` | `selector`, `value` | Fill input field |
| `type` | `selector`, `value` | Type with key delay |
| `hover` | `selector` | Hover over element |
| `scroll` | `selector` (optional) | Scroll element into view |
| `wait` | (uses pause) | Wait without action |
| `screenshot` | - | Capture screenshot |

### Wait Conditions

Each step can include a `wait` block:

```yaml
wait:
  selector: "button:has-text('Submit')"  # Wait for element
  navigation: "/success"                  # Wait for URL change
  timeout: 10000                          # Timeout in ms
```

## Branding Assets

Place branding assets in `assets/branding/`:

- `logo.png` - Watermark logo (recommended: 200x200px, transparent background)
- `intro.mp4` - Intro video clip
- `outro.mp4` - Outro video clip with CTA

## Known Limitations

### Mock Mode Required

The Playwright mock wallet returns simulated signatures that don't cryptographically validate. You **must** run the backend with `MOCK_SIGNATURES=true` for demo recording to work.

When mock mode is enabled:
- Wallet signature verification is skipped (with warning logged)
- Auth sessions work without Privado infrastructure (VERIFIER_ID not required)
- Both features are **blocked in production** for security

### TTS Caching

Generated TTS audio is cached in `.cache/tts/` based on text content and voice settings. Clear the cache to regenerate narration:

```bash
rm -rf .cache/tts/
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'demos'"

Run `make demo-setup` to ensure the virtual environment is properly configured.

### Recording fails at wallet signing

Ensure the backend is running with `MOCK_SIGNATURES=true`:

```bash
MOCK_SIGNATURES=true make run
```

### FFmpeg not found

Install FFmpeg:
```bash
# macOS
brew install ffmpeg

# Ubuntu/Debian
sudo apt install ffmpeg
```

### Playwright browser not found

```bash
cd demos/playwright && npx playwright install chromium
```
