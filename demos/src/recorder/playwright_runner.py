"""Execute Playwright recordings and manage video output."""

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..config.loader import DemoConfig


@dataclass
class RecordingResult:
    """Result from a Playwright recording run."""

    success: bool
    video_path: Path | None
    timings_path: Path | None
    screenshots: list[Path]
    error: str | None = None


class PlaywrightRunner:
    """Executes Playwright tests and manages recording outputs."""

    def __init__(self, playwright_dir: Path, output_dir: Path):
        self.playwright_dir = Path(playwright_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self, config: DemoConfig, spec_path: Path) -> RecordingResult:
        """Run a Playwright test and capture the video recording."""
        test_results_dir = self.playwright_dir / "test-results"

        # Clean previous results
        if test_results_dir.exists():
            shutil.rmtree(test_results_dir)

        # Run Playwright
        result = self._execute_playwright(spec_path)

        if not result.success:
            return result

        # Find and move outputs
        video_path = self._find_and_move_video(config.name, test_results_dir)
        timings_path = self._find_timings(config.name, test_results_dir)
        screenshots = self._find_screenshots(test_results_dir)

        return RecordingResult(
            success=True,
            video_path=video_path,
            timings_path=timings_path,
            screenshots=screenshots,
        )

    def _execute_playwright(self, spec_path: Path) -> RecordingResult:
        """Execute the Playwright test."""
        cmd = [
            "npx",
            "playwright",
            "test",
            str(spec_path),
            "--project=recording",
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=self.playwright_dir,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                return RecordingResult(
                    success=False,
                    video_path=None,
                    timings_path=None,
                    screenshots=[],
                    error=f"Playwright failed:\n{result.stderr}\n{result.stdout}",
                )

            return RecordingResult(
                success=True,
                video_path=None,
                timings_path=None,
                screenshots=[],
            )

        except subprocess.TimeoutExpired:
            return RecordingResult(
                success=False,
                video_path=None,
                timings_path=None,
                screenshots=[],
                error="Playwright test timed out after 300 seconds",
            )
        except Exception as e:
            return RecordingResult(
                success=False,
                video_path=None,
                timings_path=None,
                screenshots=[],
                error=str(e),
            )

    def _find_and_move_video(
        self, name: str, test_results_dir: Path
    ) -> Path | None:
        """Find the recorded video and move it to output directory."""
        # Playwright stores videos in test-results/<test-name>/video.webm
        video_files = list(test_results_dir.rglob("*.webm"))

        if not video_files:
            return None

        # Use the first (should be only) video file
        src_video = video_files[0]
        dest_video = self.output_dir / f"{name}_raw.webm"

        shutil.copy2(src_video, dest_video)
        return dest_video

    def _find_timings(self, name: str, test_results_dir: Path) -> Path | None:
        """Find the step timings JSON file."""
        timings_file = test_results_dir / f"{name}-timings.json"
        if timings_file.exists():
            dest = self.output_dir / f"{name}_timings.json"
            shutil.copy2(timings_file, dest)
            return dest
        return None

    def _find_screenshots(self, test_results_dir: Path) -> list[Path]:
        """Find all screenshots from the test run."""
        screenshots = []
        for png in test_results_dir.rglob("*.png"):
            dest = self.output_dir / png.name
            shutil.copy2(png, dest)
            screenshots.append(dest)
        return screenshots


def run_recording(
    config: DemoConfig,
    spec_path: Path,
    playwright_dir: str | Path,
    output_dir: str | Path,
) -> RecordingResult:
    """Convenience function to run a recording."""
    runner = PlaywrightRunner(Path(playwright_dir), Path(output_dir))
    return runner.run(config, spec_path)
