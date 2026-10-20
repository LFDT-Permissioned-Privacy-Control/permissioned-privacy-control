"""Caption generation in SRT and ASS formats."""

from dataclasses import dataclass
from pathlib import Path

from .tts import TTSSegment


@dataclass
class CaptionStyle:
    """Style configuration for captions.

    Modern YouTube/Netflix-style captions use:
    - Clean sans-serif font (Arial is universally available)
    - Semi-transparent background box (BorderStyle 3)
    - No outline, just the box
    - White text on dark background
    """

    font_name: str = "Arial"  # Universally available, clean sans-serif
    font_size: int = 52  # Good size for HD
    primary_color: str = "&HFFFFFF"  # White text (ASS format: BBGGRR)
    secondary_color: str = "&HFFFFFF"  # White
    outline_color: str = "&H000000"  # Not used with BorderStyle 3
    back_color: str = "&H80000000"  # Semi-transparent black (80 = 50% opacity)
    outline_width: int = 0  # No outline with box style
    shadow_depth: int = 0  # No shadow with box style
    border_style: int = 3  # 3 = Opaque box background (modern style)
    margin_v: int = 70  # Good distance from bottom
    margin_h: int = 40  # Horizontal margin
    alignment: int = 2  # Bottom center
    bold: bool = True  # Bold for readability
    spacing: int = 0  # Normal letter spacing


@dataclass
class Caption:
    """A single caption entry."""

    index: int
    start_time: float  # seconds
    end_time: float  # seconds
    text: str


class CaptionGenerator:
    """Generates subtitle files from narration segments."""

    def __init__(self, style: CaptionStyle | None = None):
        self.style = style or CaptionStyle()

    def generate_from_segments(
        self,
        segments: list[TTSSegment],
        step_timings: dict[str, dict],
        output_path: Path,
        format: str = "srt",
        resolution: tuple[int, int] = (1920, 1080),
    ) -> Path:
        """Generate captions from TTS segments aligned to video timings.

        Args:
            segments: TTS audio segments with text and duration
            step_timings: Recording step timing data from Playwright
            output_path: Path to write caption file
            format: Output format ('srt' or 'ass')
            resolution: Video resolution for scaling (width, height)
        """
        captions = self._align_captions(segments, step_timings)

        if format == "srt":
            return self._write_srt(captions, output_path)
        elif format == "ass":
            return self._write_ass(captions, output_path, resolution=resolution)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def generate_from_text(
        self,
        text_segments: list[tuple[float, float, str]],  # [(start, end, text), ...]
        output_path: Path,
        format: str = "srt",
        resolution: tuple[int, int] = (1920, 1080),
    ) -> Path:
        """Generate captions from raw text segments with timings."""
        captions = [
            Caption(index=i + 1, start_time=start, end_time=end, text=text)
            for i, (start, end, text) in enumerate(text_segments)
        ]

        if format == "srt":
            return self._write_srt(captions, output_path)
        elif format == "ass":
            return self._write_ass(captions, output_path, resolution=resolution)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _align_captions(
        self,
        segments: list[TTSSegment],
        step_timings: dict[str, dict],
    ) -> list[Caption]:
        """Align TTS segments to video step timings.

        CRITICAL: Uses the same placement algorithm as audio merging in ffmpeg.py
        to ensure captions are synchronized with narration audio.
        """
        captions = []
        index = 1

        # Calculate placement times using the SAME algorithm as audio merging
        # This prevents captions from being out of sync with audio
        placement_times = self._calculate_placement_times(segments, step_timings)

        for i, segment in enumerate(segments):
            start_sec = placement_times[i]
            end_sec = start_sec + segment.duration

            # Split long text into multiple captions for readability
            words = segment.text.split()
            if len(words) > 10:
                # Split into chunks of ~8 words at natural boundaries
                chunks = self._split_text(segment.text, max_words=8)
                chunk_duration = segment.duration / len(chunks)

                for j, chunk in enumerate(chunks):
                    chunk_start = start_sec + (j * chunk_duration)
                    chunk_end = chunk_start + chunk_duration
                    captions.append(
                        Caption(
                            index=index,
                            start_time=chunk_start,
                            end_time=chunk_end,
                            text=chunk,
                        )
                    )
                    index += 1
            else:
                captions.append(
                    Caption(
                        index=index,
                        start_time=start_sec,
                        end_time=end_sec,
                        text=segment.text,
                    )
                )
                index += 1

        return captions

    def _calculate_placement_times(
        self,
        segments: list[TTSSegment],
        step_timings: dict[str, dict],
        gap: float = 0.3,
    ) -> list[float]:
        """Calculate placement times for segments, preventing overlap.

        This MUST match the algorithm in FFmpegProcessor._merge_audio_segments
        to ensure captions sync with audio.
        """
        placement_times = []
        current_end_time = 0.0

        for segment in segments:
            timing = step_timings.get(segment.id, {})
            step_start_sec = timing.get("start", 0) / 1000.0

            # Place at the LATER of: step start time OR after previous ends
            # Add gap between narrations for natural pacing
            place_at = max(step_start_sec, current_end_time + gap)
            placement_times.append(place_at)

            # Track when this narration ends
            current_end_time = place_at + segment.duration

        return placement_times

    def _split_text(self, text: str, max_words: int = 8) -> list[str]:
        """Split text into chunks at natural boundaries."""
        words = text.split()
        chunks = []
        current_chunk = []

        for word in words:
            current_chunk.append(word)
            # Split at punctuation or max words
            if (
                len(current_chunk) >= max_words
                or word.endswith((".", ",", "!", "?", ";", ":"))
            ):
                chunks.append(" ".join(current_chunk))
                current_chunk = []

        if current_chunk:
            chunks.append(" ".join(current_chunk))

        return chunks

    def _write_srt(self, captions: list[Caption], output_path: Path) -> Path:
        """Write captions in SRT format."""
        output_path = output_path.with_suffix(".srt")
        lines = []

        for cap in captions:
            start = self._format_srt_time(cap.start_time)
            end = self._format_srt_time(cap.end_time)
            lines.append(f"{cap.index}")
            lines.append(f"{start} --> {end}")
            lines.append(cap.text)
            lines.append("")

        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path

    def _write_ass(
        self,
        captions: list[Caption],
        output_path: Path,
        resolution: tuple[int, int] = (1920, 1080),
    ) -> Path:
        """Write captions in ASS (Advanced SubStation Alpha) format.

        Args:
            captions: List of caption entries
            output_path: Path to write ASS file
            resolution: Video resolution for scaling (width, height)
        """
        output_path = output_path.with_suffix(".ass")
        style = self.style

        # Scale font size for resolution (base is 1080p)
        scale_factor = resolution[1] / 1080
        scaled_font_size = int(style.font_size * scale_factor)
        scaled_outline = int(style.outline_width * scale_factor)
        scaled_shadow = int(style.shadow_depth * scale_factor)
        scaled_margin_v = int(style.margin_v * scale_factor)
        scaled_margin_h = int(style.margin_h * scale_factor)

        # Bold: -1 = True, 0 = False in ASS format
        bold_value = -1 if style.bold else 0

        # BorderStyle: 1 = outline+shadow, 3 = opaque box (modern style)
        border_style = getattr(style, 'border_style', 3)

        header = f"""[Script Info]
Title: Demo Captions
ScriptType: v4.00+
WrapStyle: 0
ScaledBorderAndShadow: yes
YCbCr Matrix: TV.709
PlayResX: {resolution[0]}
PlayResY: {resolution[1]}

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Default,{style.font_name},{scaled_font_size},{style.primary_color},{style.secondary_color},{style.outline_color},{style.back_color},{bold_value},0,0,0,100,100,{style.spacing},0,{border_style},{scaled_outline},{scaled_shadow},{style.alignment},{scaled_margin_h},{scaled_margin_h},{scaled_margin_v},1

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
"""
        lines = [header.strip()]

        for cap in captions:
            start = self._format_ass_time(cap.start_time)
            end = self._format_ass_time(cap.end_time)
            # Escape special characters
            text = cap.text.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}")
            lines.append(f"Dialogue: 0,{start},{end},Default,,0,0,0,,{text}")

        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path

    def _format_srt_time(self, seconds: float) -> str:
        """Format seconds as SRT timestamp (HH:MM:SS,mmm)."""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        millis = int((seconds % 1) * 1000)
        return f"{hours:02d}:{minutes:02d}:{secs:02d},{millis:03d}"

    def _format_ass_time(self, seconds: float) -> str:
        """Format seconds as ASS timestamp (H:MM:SS.cc)."""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        centis = int((seconds % 1) * 100)
        return f"{hours}:{minutes:02d}:{secs:02d}.{centis:02d}"


def generate_captions(
    segments: list[TTSSegment],
    step_timings: dict[str, dict],
    output_path: str | Path,
    format: str = "srt",
    style: CaptionStyle | None = None,
    resolution: tuple[int, int] = (1920, 1080),
) -> Path:
    """Convenience function for generating captions.

    Args:
        segments: TTS audio segments with text and duration
        step_timings: Recording step timing data from Playwright
        output_path: Path to write caption file
        format: Output format ('srt' or 'ass')
        style: Optional custom caption styling
        resolution: Video resolution for scaling (width, height)
    """
    generator = CaptionGenerator(style)
    return generator.generate_from_segments(
        segments, step_timings, Path(output_path), format, resolution=resolution
    )
