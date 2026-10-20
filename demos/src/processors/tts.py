"""Edge TTS integration with caching (free, no API key required)."""

import asyncio
import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TTSConfig:
    """Configuration for TTS generation."""

    voice: str = "en-US-AriaNeural"  # Default Edge TTS voice
    speed: str = "+0%"  # Speed adjustment (e.g., "+10%", "-5%")
    pitch: str = "+0Hz"  # Pitch adjustment
    response_format: str = "mp3"


# Available Edge TTS voices (subset of best quality English voices)
EDGE_VOICES = {
    # US English - Natural sounding voices
    "aria": "en-US-AriaNeural",  # Female, versatile
    "jenny": "en-US-JennyNeural",  # Female, friendly
    "guy": "en-US-GuyNeural",  # Male, professional
    "davis": "en-US-DavisNeural",  # Male, conversational
    "amber": "en-US-AmberNeural",  # Female, warm
    "ana": "en-US-AnaNeural",  # Female, child
    "ashley": "en-US-AshleyNeural",  # Female, casual
    "brandon": "en-US-BrandonNeural",  # Male, casual
    "christopher": "en-US-ChristopherNeural",  # Male, professional
    "cora": "en-US-CoraNeural",  # Female, professional
    "elizabeth": "en-US-ElizabethNeural",  # Female, professional
    "eric": "en-US-EricNeural",  # Male, versatile
    "jacob": "en-US-JacobNeural",  # Male, casual
    "michelle": "en-US-MichelleNeural",  # Female, friendly
    "monica": "en-US-MonicaNeural",  # Female, professional
    "roger": "en-US-RogerNeural",  # Male, professional
    "steffan": "en-US-SteffanNeural",  # Male, friendly
    # UK English
    "sonia": "en-GB-SoniaNeural",  # Female, professional
    "ryan": "en-GB-RyanNeural",  # Male, professional
    # Map OpenAI voice names to similar Edge voices for compatibility
    "alloy": "en-US-JennyNeural",
    "echo": "en-US-GuyNeural",
    "fable": "en-GB-SoniaNeural",
    "onyx": "en-US-DavisNeural",
    "nova": "en-US-AriaNeural",
    "shimmer": "en-US-MichelleNeural",
}


@dataclass
class TTSSegment:
    """A single TTS segment with its audio file."""

    id: str
    text: str
    audio_path: Path
    duration: float  # seconds


class TTSProcessor:
    """Generates TTS audio using Microsoft Edge TTS (free, no API key required)."""

    VOICES = list(EDGE_VOICES.keys())

    def __init__(self, cache_dir: Path, api_key: str | None = None):
        """Initialize TTS processor.

        Args:
            cache_dir: Directory for caching generated audio
            api_key: Ignored (kept for API compatibility with OpenAI version)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        # Note: api_key is ignored - Edge TTS is free

    def generate_narration(
        self,
        segments: list[tuple[str, str]],  # [(id, text), ...]
        config: TTSConfig | None = None,
    ) -> list[TTSSegment]:
        """Generate TTS audio for multiple narration segments."""
        config = config or TTSConfig()
        results = []

        for segment_id, text in segments:
            if not text.strip():
                continue

            audio_path = self._get_or_generate(segment_id, text, config)
            duration = self._get_audio_duration(audio_path)

            results.append(
                TTSSegment(
                    id=segment_id,
                    text=text,
                    audio_path=audio_path,
                    duration=duration,
                )
            )

        return results

    def generate_single(
        self, text: str, output_path: Path, config: TTSConfig | None = None
    ) -> TTSSegment:
        """Generate TTS for a single text segment."""
        config = config or TTSConfig()
        segment_id = self._hash_text(text)

        # Check cache first
        cached = self._get_cached(segment_id, config)
        if cached and cached.exists():
            # Copy to output path
            import shutil
            shutil.copy2(cached, output_path)
        else:
            # Generate new
            asyncio.run(self._generate_audio(text, output_path, config))
            # Cache it
            self._cache_audio(segment_id, output_path, config)

        duration = self._get_audio_duration(output_path)
        return TTSSegment(
            id=segment_id,
            text=text,
            audio_path=output_path,
            duration=duration,
        )

    def _get_or_generate(
        self, segment_id: str, text: str, config: TTSConfig
    ) -> Path:
        """Get from cache or generate new audio."""
        cache_key = self._make_cache_key(segment_id, text, config)
        cached_path = self.cache_dir / f"{cache_key}.{config.response_format}"

        if cached_path.exists():
            return cached_path

        # Generate new audio
        asyncio.run(self._generate_audio(text, cached_path, config))
        return cached_path

    async def _generate_audio(
        self, text: str, output_path: Path, config: TTSConfig
    ) -> None:
        """Generate audio using Edge TTS."""
        import edge_tts

        # Resolve voice name (support both short names and full voice IDs)
        voice = EDGE_VOICES.get(config.voice.lower(), config.voice)

        # Create communicate object
        communicate = edge_tts.Communicate(
            text,
            voice=voice,
            rate=config.speed,
            pitch=config.pitch,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        await communicate.save(str(output_path))

    def _get_cached(self, segment_id: str, config: TTSConfig) -> Path | None:
        """Check if audio is already cached."""
        pattern = f"{segment_id}_*.{config.response_format}"
        matches = list(self.cache_dir.glob(pattern))
        return matches[0] if matches else None

    def _cache_audio(
        self, segment_id: str, audio_path: Path, config: TTSConfig
    ) -> None:
        """Cache audio file."""
        import shutil
        cache_key = self._make_cache_key(segment_id, "", config)
        cached_path = self.cache_dir / f"{cache_key}.{config.response_format}"
        if not cached_path.exists():
            shutil.copy2(audio_path, cached_path)

    def _make_cache_key(
        self, segment_id: str, text: str, config: TTSConfig
    ) -> str:
        """Create a cache key for the segment."""
        content = f"{segment_id}:{text}:{config.voice}:{config.speed}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _hash_text(self, text: str) -> str:
        """Create a short hash of text for identification."""
        return hashlib.sha256(text.encode()).hexdigest()[:12]

    def _get_audio_duration(self, audio_path: Path) -> float:
        """Get duration of audio file using ffprobe."""
        try:
            result = subprocess.run(
                [
                    "ffprobe",
                    "-v", "error",
                    "-show_entries", "format=duration",
                    "-of", "default=noprint_wrappers=1:nokey=1",
                    str(audio_path),
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return float(result.stdout.strip())
        except Exception:
            # Fallback: estimate based on text length (150 wpm average)
            return 0.0


def generate_narration(
    segments: list[tuple[str, str]],
    cache_dir: str | Path,
    config: TTSConfig | None = None,
) -> list[TTSSegment]:
    """Convenience function for generating narration."""
    processor = TTSProcessor(Path(cache_dir))
    return processor.generate_narration(segments, config)
