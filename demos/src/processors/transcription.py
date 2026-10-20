"""Whisper-based transcription for generating captions from audio/video."""

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TranscriptionSegment:
    """A single transcribed segment."""

    start: float
    end: float
    text: str


@dataclass
class TranscriptionResult:
    """Complete transcription result."""

    segments: list[TranscriptionSegment]
    full_text: str
    language: str


class TranscriptionProcessor:
    """Transcribes audio/video using Whisper."""

    def __init__(self, model_name: str = "base"):
        """
        Initialize transcription processor.

        Args:
            model_name: Whisper model to use (tiny, base, small, medium, large)
        """
        self.model_name = model_name
        self._model = None

    def _load_model(self):
        """Lazy load the Whisper model."""
        if self._model is None:
            import whisper
            self._model = whisper.load_model(self.model_name)
        return self._model

    def transcribe_audio(
        self, audio_path: Path, language: str | None = None
    ) -> TranscriptionResult:
        """Transcribe an audio file."""
        model = self._load_model()

        options = {"word_timestamps": True}
        if language:
            options["language"] = language

        result = model.transcribe(str(audio_path), **options)

        segments = [
            TranscriptionSegment(
                start=seg["start"],
                end=seg["end"],
                text=seg["text"].strip(),
            )
            for seg in result["segments"]
        ]

        return TranscriptionResult(
            segments=segments,
            full_text=result["text"].strip(),
            language=result.get("language", "en"),
        )

    def transcribe_video(
        self, video_path: Path, language: str | None = None
    ) -> TranscriptionResult:
        """Transcribe audio from a video file."""
        # Extract audio to temporary file
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            self._extract_audio(video_path, tmp_path)
            return self.transcribe_audio(tmp_path, language)
        finally:
            tmp_path.unlink(missing_ok=True)

    def _extract_audio(self, video_path: Path, output_path: Path) -> None:
        """Extract audio from video using FFmpeg."""
        cmd = [
            "ffmpeg", "-y",
            "-i", str(video_path),
            "-vn",
            "-acodec", "pcm_s16le",
            "-ar", "16000",
            "-ac", "1",
            str(output_path),
        ]
        subprocess.run(cmd, capture_output=True, check=True)

    def generate_srt(
        self, result: TranscriptionResult, output_path: Path
    ) -> Path:
        """Generate SRT subtitle file from transcription."""
        output_path = output_path.with_suffix(".srt")
        lines = []

        for i, seg in enumerate(result.segments, 1):
            start = self._format_srt_time(seg.start)
            end = self._format_srt_time(seg.end)
            lines.append(f"{i}")
            lines.append(f"{start} --> {end}")
            lines.append(seg.text)
            lines.append("")

        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path

    def _format_srt_time(self, seconds: float) -> str:
        """Format seconds as SRT timestamp."""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        millis = int((seconds % 1) * 1000)
        return f"{hours:02d}:{minutes:02d}:{secs:02d},{millis:03d}"


def transcribe(
    input_path: str | Path,
    model_name: str = "base",
    language: str | None = None,
) -> TranscriptionResult:
    """Convenience function for transcription."""
    processor = TranscriptionProcessor(model_name)
    path = Path(input_path)

    if path.suffix.lower() in [".mp3", ".wav", ".m4a", ".flac", ".ogg"]:
        return processor.transcribe_audio(path, language)
    else:
        return processor.transcribe_video(path, language)
