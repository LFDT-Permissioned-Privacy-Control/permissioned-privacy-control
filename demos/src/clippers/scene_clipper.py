"""FFmpeg-based scene detection and clip extraction."""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SceneChange:
    """A detected scene change point."""

    timestamp: float
    score: float  # Scene change confidence (0-1)


@dataclass
class Clip:
    """An extracted video clip."""

    id: str
    start: float
    end: float
    duration: float
    path: Path
    score: float  # Quality/importance score


@dataclass
class ClippingConfig:
    """Configuration for clip extraction."""

    min_duration: float = 15.0  # Minimum clip duration in seconds
    max_duration: float = 60.0  # Maximum clip duration
    target_count: int = 10  # Target number of clips to extract
    scene_threshold: float = 0.3  # Scene change detection threshold
    padding: float = 0.5  # Padding around scene cuts


class SceneClipper:
    """Detects scenes and extracts clips from video."""

    def __init__(self, config: ClippingConfig | None = None):
        self.config = config or ClippingConfig()

    def detect_scenes(self, video_path: Path) -> list[SceneChange]:
        """Detect scene changes using FFmpeg."""
        # Use ffprobe with scene detection filter
        cmd = [
            "ffprobe",
            "-v", "quiet",
            "-show_frames",
            "-of", "json",
            "-f", "lavfi",
            f"movie={video_path},select='gt(scene,{self.config.scene_threshold})'",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            data = json.loads(result.stdout)

            scenes = []
            for frame in data.get("frames", []):
                timestamp = float(frame.get("pts_time", 0))
                # Scene score from frame metadata
                score = float(frame.get("tags", {}).get("lavfi.scene_score", 0.5))
                scenes.append(SceneChange(timestamp=timestamp, score=score))

            return scenes
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            # Fallback: use regular interval detection
            return self._detect_by_interval(video_path)

    def _detect_by_interval(self, video_path: Path) -> list[SceneChange]:
        """Fallback scene detection using fixed intervals."""
        duration = self._get_video_duration(video_path)
        interval = self.config.max_duration

        scenes = []
        timestamp = 0.0
        while timestamp < duration:
            scenes.append(SceneChange(timestamp=timestamp, score=0.5))
            timestamp += interval

        return scenes

    def extract_clips(
        self,
        video_path: Path,
        output_dir: Path,
        narration_boundaries: list[tuple[float, float]] | None = None,
    ) -> list[Clip]:
        """
        Extract clips from video based on scene detection and narration.

        Args:
            video_path: Path to source video
            output_dir: Directory for clip output
            narration_boundaries: Optional list of (start, end) timestamps for narration segments
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Get video duration
        duration = self._get_video_duration(video_path)

        # Detect scene changes
        scenes = self.detect_scenes(video_path)

        # Build clip boundaries
        if narration_boundaries:
            # Use narration-aligned boundaries
            boundaries = self._align_to_narration(scenes, narration_boundaries, duration)
        else:
            # Use scene-based boundaries
            boundaries = self._build_boundaries(scenes, duration)

        # Score and select clips
        scored_boundaries = self._score_clips(boundaries, scenes)
        selected = self._select_clips(scored_boundaries)

        # Extract clips
        clips = []
        for i, (start, end, score) in enumerate(selected):
            clip_id = f"clip_{i + 1:03d}"
            clip_path = output_dir / f"{clip_id}.mp4"

            self._extract_clip(video_path, start, end, clip_path)

            clips.append(
                Clip(
                    id=clip_id,
                    start=start,
                    end=end,
                    duration=end - start,
                    path=clip_path,
                    score=score,
                )
            )

        return clips

    def _build_boundaries(
        self, scenes: list[SceneChange], duration: float
    ) -> list[tuple[float, float]]:
        """Build clip boundaries from scene changes."""
        if not scenes:
            # Single clip for entire video
            return [(0.0, min(duration, self.config.max_duration))]

        boundaries = []
        scene_times = [0.0] + [s.timestamp for s in scenes] + [duration]

        for i in range(len(scene_times) - 1):
            start = scene_times[i]
            end = scene_times[i + 1]

            # Skip if too short
            if end - start < self.config.min_duration:
                continue

            # Split if too long
            while end - start > self.config.max_duration:
                mid = start + self.config.max_duration
                boundaries.append((start, mid))
                start = mid

            if end - start >= self.config.min_duration:
                boundaries.append((start, end))

        return boundaries

    def _align_to_narration(
        self,
        scenes: list[SceneChange],
        narration: list[tuple[float, float]],
        duration: float,
    ) -> list[tuple[float, float]]:
        """Align clip boundaries to narration segments."""
        boundaries = []

        for start, end in narration:
            # Extend to include padding
            clip_start = max(0, start - self.config.padding)
            clip_end = min(duration, end + self.config.padding)

            # Find nearest scene change before start
            for scene in reversed(scenes):
                if scene.timestamp <= start:
                    clip_start = max(clip_start, scene.timestamp)
                    break

            # Find nearest scene change after end
            for scene in scenes:
                if scene.timestamp >= end:
                    clip_end = min(clip_end, scene.timestamp)
                    break

            # Enforce min/max duration
            clip_duration = clip_end - clip_start
            if clip_duration < self.config.min_duration:
                # Extend clip
                extension = (self.config.min_duration - clip_duration) / 2
                clip_start = max(0, clip_start - extension)
                clip_end = min(duration, clip_end + extension)

            if clip_end - clip_start > self.config.max_duration:
                clip_end = clip_start + self.config.max_duration

            boundaries.append((clip_start, clip_end))

        return boundaries

    def _score_clips(
        self, boundaries: list[tuple[float, float]], scenes: list[SceneChange]
    ) -> list[tuple[float, float, float]]:
        """Score clips based on visual activity and content."""
        scored = []

        for start, end in boundaries:
            # Count scene changes within clip
            scene_count = sum(
                1 for s in scenes if start <= s.timestamp <= end
            )

            # Base score from scene activity
            activity_score = min(1.0, scene_count / 5)

            # Prefer clips in the middle of the video (more likely interesting)
            position_score = 1.0 - abs(0.5 - (start + end) / 2 / max(end, 1)) * 0.5

            # Prefer longer clips up to a point
            duration = end - start
            length_score = min(1.0, duration / 30)

            # Combined score
            score = (activity_score * 0.4 + position_score * 0.3 + length_score * 0.3)
            scored.append((start, end, score))

        return scored

    def _select_clips(
        self, scored: list[tuple[float, float, float]]
    ) -> list[tuple[float, float, float]]:
        """Select the best clips based on scores."""
        # Sort by score descending
        sorted_clips = sorted(scored, key=lambda x: x[2], reverse=True)

        # Select top clips, avoiding overlaps
        selected = []
        for clip in sorted_clips:
            start, end, score = clip

            # Check for overlap with already selected clips
            overlaps = any(
                not (end <= s[0] or start >= s[1]) for s in selected
            )

            if not overlaps:
                selected.append(clip)

            if len(selected) >= self.config.target_count:
                break

        # Sort by timestamp for output
        return sorted(selected, key=lambda x: x[0])

    def _extract_clip(
        self, video_path: Path, start: float, end: float, output_path: Path
    ) -> None:
        """Extract a clip from video."""
        cmd = [
            "ffmpeg", "-y",
            "-ss", str(start),
            "-i", str(video_path),
            "-t", str(end - start),
            "-c:v", "libx264",
            "-preset", "fast",
            "-crf", "18",
            "-c:a", "aac",
            "-b:a", "192k",
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


def extract_clips(
    video_path: str | Path,
    output_dir: str | Path,
    narration_boundaries: list[tuple[float, float]] | None = None,
    config: ClippingConfig | None = None,
) -> list[Clip]:
    """Convenience function for clip extraction."""
    clipper = SceneClipper(config)
    return clipper.extract_clips(
        Path(video_path), Path(output_dir), narration_boundaries
    )
