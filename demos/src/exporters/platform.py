"""Platform-specific video export with proper aspect ratios and safe zones."""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..clippers.scene_clipper import Clip


@dataclass
class PlatformConfig:
    """Configuration for a social media platform."""

    name: str
    aspect_ratio: str  # "16:9", "9:16", "1:1", "4:5"
    resolution: tuple[int, int]
    max_duration: float  # seconds
    safe_zone: tuple[int, int, int, int]  # top, right, bottom, left margins
    supports_captions: bool = True


# Platform presets
PLATFORMS = {
    "tiktok": PlatformConfig(
        name="TikTok",
        aspect_ratio="9:16",
        resolution=(1080, 1920),
        max_duration=180,
        safe_zone=(150, 50, 200, 50),  # Account for UI overlays
    ),
    "reels": PlatformConfig(
        name="Instagram Reels",
        aspect_ratio="9:16",
        resolution=(1080, 1920),
        max_duration=90,
        safe_zone=(120, 50, 180, 50),
    ),
    "shorts": PlatformConfig(
        name="YouTube Shorts",
        aspect_ratio="9:16",
        resolution=(1080, 1920),
        max_duration=60,
        safe_zone=(100, 50, 150, 50),
    ),
    "linkedin": PlatformConfig(
        name="LinkedIn",
        aspect_ratio="1:1",
        resolution=(1080, 1080),
        max_duration=600,
        safe_zone=(50, 50, 50, 50),
    ),
    "twitter": PlatformConfig(
        name="Twitter/X",
        aspect_ratio="16:9",
        resolution=(1920, 1080),
        max_duration=140,
        safe_zone=(50, 50, 50, 50),
    ),
    "youtube": PlatformConfig(
        name="YouTube",
        aspect_ratio="16:9",
        resolution=(1920, 1080),
        max_duration=3600,
        safe_zone=(50, 50, 50, 50),
    ),
}


@dataclass
class ExportResult:
    """Result from exporting a clip."""

    platform: str
    path: Path
    resolution: tuple[int, int]
    duration: float
    metadata: dict


class PlatformExporter:
    """Exports videos optimized for different social media platforms."""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)

    def export_clip(
        self,
        clip: Clip,
        platform: str,
        captions_path: Path | None = None,
    ) -> ExportResult:
        """Export a single clip for a specific platform."""
        config = PLATFORMS.get(platform)
        if not config:
            raise ValueError(f"Unknown platform: {platform}")

        # Create platform output directory
        platform_dir = self.output_dir / platform
        platform_dir.mkdir(parents=True, exist_ok=True)

        output_path = platform_dir / f"{clip.id}.mp4"

        # Transform video for platform
        self._transform_video(clip.path, output_path, config, captions_path)

        # Get actual duration
        duration = self._get_duration(output_path)

        return ExportResult(
            platform=platform,
            path=output_path,
            resolution=config.resolution,
            duration=duration,
            metadata={
                "source_clip": clip.id,
                "aspect_ratio": config.aspect_ratio,
                "platform_name": config.name,
            },
        )

    def export_all_platforms(
        self,
        clip: Clip,
        platforms: list[str] | None = None,
        captions_path: Path | None = None,
    ) -> list[ExportResult]:
        """Export a clip to multiple platforms."""
        platforms = platforms or ["tiktok", "reels", "shorts", "linkedin"]
        results = []

        for platform in platforms:
            config = PLATFORMS.get(platform)
            if not config:
                continue

            # Skip if clip is too long for platform
            if clip.duration > config.max_duration:
                continue

            result = self.export_clip(clip, platform, captions_path)
            results.append(result)

        return results

    def _transform_video(
        self,
        input_path: Path,
        output_path: Path,
        config: PlatformConfig,
        captions_path: Path | None = None,
    ) -> None:
        """Transform video for platform specifications."""
        width, height = config.resolution

        # Build filter chain
        filters = []

        # Scale and crop/pad for aspect ratio
        source_aspect = self._get_aspect_ratio(input_path)
        target_aspect = width / height

        if abs(source_aspect - target_aspect) > 0.01:
            if source_aspect > target_aspect:
                # Source is wider - crop sides or letterbox
                filters.append(
                    f"scale={width}:-1,crop={width}:{height}"
                )
            else:
                # Source is taller - crop top/bottom or pillarbox
                filters.append(
                    f"scale=-1:{height},crop={width}:{height}"
                )
        else:
            filters.append(f"scale={width}:{height}")

        # Add captions with safe zone positioning
        if captions_path and captions_path.exists() and config.supports_captions:
            escaped_path = str(captions_path).replace(":", "\\:").replace("\\", "/")
            if captions_path.suffix == ".ass":
                filters.append(f"ass='{escaped_path}'")
            else:
                # Adjust subtitle position for safe zone
                margin_v = config.safe_zone[2]  # bottom margin
                filters.append(
                    f"subtitles='{escaped_path}':force_style='MarginV={margin_v}'"
                )

        filter_str = ",".join(filters)

        cmd = [
            "ffmpeg", "-y",
            "-i", str(input_path),
            "-vf", filter_str,
            "-c:v", "libx264",
            "-preset", "medium",
            "-crf", "18",
            "-c:a", "aac",
            "-b:a", "192k",
            "-movflags", "+faststart",  # Optimize for streaming
            str(output_path),
        ]

        subprocess.run(cmd, capture_output=True, check=True)

    def _get_aspect_ratio(self, video_path: Path) -> float:
        """Get aspect ratio of video."""
        result = subprocess.run(
            [
                "ffprobe",
                "-v", "error",
                "-select_streams", "v:0",
                "-show_entries", "stream=width,height",
                "-of", "json",
                str(video_path),
            ],
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
        stream = data["streams"][0]
        return stream["width"] / stream["height"]

    def _get_duration(self, video_path: Path) -> float:
        """Get duration of video."""
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

    def write_metadata(
        self, clip: Clip, results: list[ExportResult], copy_data: dict | None = None
    ) -> Path:
        """Write metadata JSON for a clip and its exports."""
        metadata = {
            "clip_id": clip.id,
            "source": {
                "start": clip.start,
                "end": clip.end,
                "duration": clip.duration,
                "score": clip.score,
            },
            "exports": [
                {
                    "platform": r.platform,
                    "path": str(r.path.relative_to(self.output_dir)),
                    "resolution": list(r.resolution),
                    "duration": r.duration,
                }
                for r in results
            ],
        }

        if copy_data:
            metadata["copy"] = copy_data

        metadata_path = self.output_dir / f"{clip.id}_metadata.json"
        metadata_path.write_text(json.dumps(metadata, indent=2))
        return metadata_path


def export_for_platforms(
    clip: Clip,
    output_dir: str | Path,
    platforms: list[str] | None = None,
    captions_path: Path | None = None,
) -> list[ExportResult]:
    """Convenience function for platform export."""
    exporter = PlatformExporter(Path(output_dir))
    return exporter.export_all_platforms(clip, platforms, captions_path)
