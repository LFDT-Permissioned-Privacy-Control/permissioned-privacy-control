"""FFmpeg video composition and processing."""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .tts import TTSSegment


@dataclass
class CompositionConfig:
    """Configuration for video composition."""

    resolution: tuple[int, int] = (1920, 1080)
    fps: int = 60
    video_codec: str = "libx264"
    audio_codec: str = "aac"
    video_bitrate: str = "25M"
    audio_bitrate: str = "320k"
    preset: str = "slow"  # Better compression efficiency
    crf: int = 15  # Near-lossless quality (lower = higher quality)
    # Additional high quality settings
    profile: str = "high"
    level: str = "4.2"
    pix_fmt: str = "yuv420p"


@dataclass
class WatermarkConfig:
    """Configuration for watermark overlay."""

    path: Path
    position: str = "bottom-right"
    opacity: float = 0.7
    margin: int = 20
    scale: float = 0.1  # Relative to video width


class FFmpegProcessor:
    """Handles all FFmpeg video processing operations."""

    def __init__(self, config: CompositionConfig | None = None):
        self.config = config or CompositionConfig()
        self._verify_ffmpeg()

    def _verify_ffmpeg(self) -> None:
        """Verify FFmpeg is available."""
        try:
            subprocess.run(
                ["ffmpeg", "-version"],
                capture_output=True,
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("FFmpeg not found. Please install FFmpeg.")

    def compose_demo(
        self,
        video_path: Path,
        audio_segments: list[TTSSegment],
        step_timings: dict[str, dict],
        output_path: Path,
        captions_path: Path | None = None,
        watermark: WatermarkConfig | None = None,
        intro_path: Path | None = None,
        outro_path: Path | None = None,
    ) -> Path:
        """
        Compose a complete demo video with narration, captions, and branding.

        Pipeline:
        1. Merge audio segments at correct timestamps
        2. Overlay audio on video
        3. Add captions (burn-in)
        4. Add watermark
        5. Concatenate intro/outro
        """
        work_dir = output_path.parent / "work"
        work_dir.mkdir(exist_ok=True)

        # Step 1: Create merged audio track
        merged_audio = work_dir / "merged_audio.m4a"
        self._merge_audio_segments(
            audio_segments, step_timings, merged_audio, self._get_video_duration(video_path)
        )

        # Step 2: Combine video with audio
        video_with_audio = work_dir / "video_with_audio.mp4"
        self._combine_video_audio(video_path, merged_audio, video_with_audio)

        # Step 3: Add captions if provided
        if captions_path and captions_path.exists():
            captioned = work_dir / "captioned.mp4"
            self._burn_captions(video_with_audio, captions_path, captioned)
            current_video = captioned
        else:
            current_video = video_with_audio

        # Step 4: Add watermark if provided
        if watermark and watermark.path.exists():
            watermarked = work_dir / "watermarked.mp4"
            self._add_watermark(current_video, watermark, watermarked)
            current_video = watermarked

        # Step 5: Concatenate intro/outro
        parts = []
        if intro_path and intro_path.exists():
            parts.append(intro_path)
        parts.append(current_video)
        if outro_path and outro_path.exists():
            parts.append(outro_path)

        if len(parts) > 1:
            self._concatenate_videos(parts, output_path)
        else:
            # Just copy/transcode the final video
            self._transcode(current_video, output_path)

        return output_path

    def _merge_audio_segments(
        self,
        segments: list[TTSSegment],
        step_timings: dict[str, dict],
        output_path: Path,
        total_duration: float,
    ) -> None:
        """Merge audio segments at their correct timestamps, preventing overlap."""
        if not segments:
            # Create silent audio track
            self._create_silent_audio(output_path, total_duration)
            return

        # Build FFmpeg filter for placing audio at correct times
        # Key fix: ensure narrations don't overlap by tracking when each ends
        inputs = []
        filter_parts = []

        # Calculate placement times that prevent overlap
        placement_times = []
        current_end_time = 0.0

        for segment in segments:
            timing = step_timings.get(segment.id, {})
            step_start_sec = timing.get("start", 0) / 1000.0

            # Place narration at the later of: step start time, or after previous narration ends
            # Add a small gap (0.3s) between narrations for natural pacing
            place_at = max(step_start_sec, current_end_time + 0.3)
            placement_times.append(place_at)

            # Track when this narration ends
            current_end_time = place_at + segment.duration

        for i, segment in enumerate(segments):
            place_at_ms = int(placement_times[i] * 1000)

            inputs.extend(["-i", str(segment.audio_path)])
            # Delay each audio segment to its calculated placement time
            filter_parts.append(f"[{i}:a]adelay={place_at_ms}|{place_at_ms}[a{i}]")

        # Mix all delayed audio streams (concat mode to avoid volume reduction)
        mix_inputs = "".join(f"[a{i}]" for i in range(len(segments)))
        filter_parts.append(f"{mix_inputs}amix=inputs={len(segments)}:duration=longest:normalize=0[aout]")

        filter_complex = ";".join(filter_parts)

        cmd = [
            "ffmpeg", "-y",
            *inputs,
            "-filter_complex", filter_complex,
            "-map", "[aout]",
            "-t", str(total_duration),
            "-c:a", self.config.audio_codec,
            "-b:a", self.config.audio_bitrate,
            str(output_path),
        ]

        subprocess.run(cmd, capture_output=True, check=True)

    def _combine_video_audio(
        self, video_path: Path, audio_path: Path, output_path: Path
    ) -> None:
        """Combine video with audio track."""
        cmd = [
            "ffmpeg", "-y",
            "-i", str(video_path),
            "-i", str(audio_path),
            "-c:v", self.config.video_codec,
            "-preset", self.config.preset,
            "-crf", str(self.config.crf),
            "-profile:v", self.config.profile,
            "-level:v", self.config.level,
            "-pix_fmt", self.config.pix_fmt,
            "-c:a", self.config.audio_codec,
            "-b:a", self.config.audio_bitrate,
            "-map", "0:v:0",
            "-map", "1:a:0",
            "-shortest",
            str(output_path),
        ]

        subprocess.run(cmd, capture_output=True, check=True)

    def _burn_captions(
        self, video_path: Path, captions_path: Path, output_path: Path
    ) -> None:
        """Burn captions into video."""
        # Escape path for FFmpeg filter
        escaped_path = str(captions_path).replace(":", "\\:").replace("\\", "/")

        if captions_path.suffix == ".ass":
            filter_str = f"ass='{escaped_path}'"
        else:
            filter_str = f"subtitles='{escaped_path}'"

        cmd = [
            "ffmpeg", "-y",
            "-i", str(video_path),
            "-vf", filter_str,
            "-c:v", self.config.video_codec,
            "-preset", self.config.preset,
            "-crf", str(self.config.crf),
            "-profile:v", self.config.profile,
            "-level:v", self.config.level,
            "-pix_fmt", self.config.pix_fmt,
            "-c:a", "copy",
            str(output_path),
        ]

        subprocess.run(cmd, capture_output=True, check=True)

    def _add_watermark(
        self, video_path: Path, watermark: WatermarkConfig, output_path: Path
    ) -> None:
        """Add watermark overlay to video."""
        # Calculate position based on setting
        w, h = self.config.resolution
        margin = watermark.margin
        scale_w = int(w * watermark.scale)

        positions = {
            "top-left": f"{margin}:{margin}",
            "top-right": f"W-w-{margin}:{margin}",
            "bottom-left": f"{margin}:H-h-{margin}",
            "bottom-right": f"W-w-{margin}:H-h-{margin}",
            "center": "(W-w)/2:(H-h)/2",
        }
        pos = positions.get(watermark.position, positions["bottom-right"])

        filter_str = (
            f"[1:v]scale={scale_w}:-1,format=rgba,"
            f"colorchannelmixer=aa={watermark.opacity}[wm];"
            f"[0:v][wm]overlay={pos}"
        )

        cmd = [
            "ffmpeg", "-y",
            "-i", str(video_path),
            "-i", str(watermark.path),
            "-filter_complex", filter_str,
            "-c:v", self.config.video_codec,
            "-preset", self.config.preset,
            "-crf", str(self.config.crf),
            "-profile:v", self.config.profile,
            "-level:v", self.config.level,
            "-pix_fmt", self.config.pix_fmt,
            "-c:a", "copy",
            str(output_path),
        ]

        subprocess.run(cmd, capture_output=True, check=True)

    def _concatenate_videos(self, parts: list[Path], output_path: Path) -> None:
        """Concatenate multiple video files."""
        # Create concat file
        concat_file = output_path.parent / "concat.txt"
        with open(concat_file, "w") as f:
            for part in parts:
                f.write(f"file '{part}'\n")

        cmd = [
            "ffmpeg", "-y",
            "-f", "concat",
            "-safe", "0",
            "-i", str(concat_file),
            "-c:v", self.config.video_codec,
            "-preset", self.config.preset,
            "-crf", str(self.config.crf),
            "-profile:v", self.config.profile,
            "-level:v", self.config.level,
            "-pix_fmt", self.config.pix_fmt,
            "-c:a", self.config.audio_codec,
            "-b:a", self.config.audio_bitrate,
            str(output_path),
        ]

        subprocess.run(cmd, capture_output=True, check=True)
        concat_file.unlink()

    def _transcode(
        self,
        input_path: Path,
        output_path: Path,
        fade_in: float = 0.5,
        fade_out: float = 0.5,
    ) -> None:
        """Transcode video to output format with fade effects."""
        # Get video duration for fade out calculation
        duration = self._get_video_duration(input_path)
        fade_out_start = max(0, duration - fade_out)

        # Build filter for fade effects
        video_filter = f"fade=t=in:st=0:d={fade_in},fade=t=out:st={fade_out_start}:d={fade_out}"
        audio_filter = f"afade=t=in:st=0:d={fade_in},afade=t=out:st={fade_out_start}:d={fade_out}"

        cmd = [
            "ffmpeg", "-y",
            "-i", str(input_path),
            "-vf", video_filter,
            "-af", audio_filter,
            "-c:v", self.config.video_codec,
            "-preset", self.config.preset,
            "-crf", str(self.config.crf),
            "-profile:v", self.config.profile,
            "-level:v", self.config.level,
            "-pix_fmt", self.config.pix_fmt,
            "-c:a", self.config.audio_codec,
            "-b:a", self.config.audio_bitrate,
            str(output_path),
        ]

        subprocess.run(cmd, capture_output=True, check=True)

    def _create_silent_audio(self, output_path: Path, duration: float) -> None:
        """Create a silent audio track."""
        cmd = [
            "ffmpeg", "-y",
            "-f", "lavfi",
            "-i", f"anullsrc=r=44100:cl=stereo",
            "-t", str(duration),
            "-c:a", self.config.audio_codec,
            "-b:a", self.config.audio_bitrate,
            str(output_path),
        ]

        subprocess.run(cmd, capture_output=True, check=True)

    def _get_video_duration(self, video_path: Path) -> float:
        """Get duration of video file."""
        result = subprocess.run(
            [
                "ffprobe",
                "-v", "error",
                "-show_entries", "format=duration",
                "-of", "default=noprint_wrappers=1:nokey=1",
                str(video_path),
            ],
            capture_output=True,
            text=True,
        )
        return float(result.stdout.strip())

    def extract_frame(
        self, video_path: Path, timestamp: float, output_path: Path
    ) -> Path:
        """Extract a single frame from video."""
        cmd = [
            "ffmpeg", "-y",
            "-ss", str(timestamp),
            "-i", str(video_path),
            "-frames:v", "1",
            "-q:v", "2",
            str(output_path),
        ]

        subprocess.run(cmd, capture_output=True, check=True)
        return output_path

    def resize_video(
        self,
        input_path: Path,
        output_path: Path,
        width: int,
        height: int,
        crop: bool = True,
    ) -> Path:
        """Resize video to specified dimensions."""
        if crop:
            # Scale and crop to fill
            filter_str = (
                f"scale={width}:{height}:force_original_aspect_ratio=increase,"
                f"crop={width}:{height}"
            )
        else:
            # Scale with padding
            filter_str = (
                f"scale={width}:{height}:force_original_aspect_ratio=decrease,"
                f"pad={width}:{height}:(ow-iw)/2:(oh-ih)/2"
            )

        cmd = [
            "ffmpeg", "-y",
            "-i", str(input_path),
            "-vf", filter_str,
            "-c:v", self.config.video_codec,
            "-preset", self.config.preset,
            "-crf", str(self.config.crf),
            "-profile:v", self.config.profile,
            "-level:v", self.config.level,
            "-pix_fmt", self.config.pix_fmt,
            "-c:a", "copy",
            str(output_path),
        ]

        subprocess.run(cmd, capture_output=True, check=True)
        return output_path


def compose_demo(
    video_path: str | Path,
    audio_segments: list[TTSSegment],
    step_timings: dict[str, dict],
    output_path: str | Path,
    **kwargs,
) -> Path:
    """Convenience function for composing a demo video."""
    processor = FFmpegProcessor()
    return processor.compose_demo(
        Path(video_path),
        audio_segments,
        step_timings,
        Path(output_path),
        **kwargs,
    )
