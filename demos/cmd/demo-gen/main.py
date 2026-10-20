#!/usr/bin/env python3
"""
Demo Generator CLI

Generate promotional demo videos from Open Privacy Suite application.

Usage:
    python -m demos.cmd.demo-gen.main generate <config>
    python -m demos.cmd.demo-gen.main record <config>
    python -m demos.cmd.demo-gen.main process <config>
    python -m demos.cmd.demo-gen.main clip <video>
"""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from demos.src.config.loader import load_config
from demos.src.recorder.spec_generator import SpecGenerator
from demos.src.recorder.playwright_runner import PlaywrightRunner
from demos.src.processors.tts import TTSProcessor, TTSConfig
from demos.src.processors.captions import CaptionGenerator
from demos.src.processors.ffmpeg import FFmpegProcessor, WatermarkConfig, CompositionConfig
from demos.src.clippers.scene_clipper import SceneClipper, ClippingConfig
from demos.src.exporters.platform import PlatformExporter
from demos.src.generators.copy import CopyGenerator, CopyConfig

console = Console()

# Base directories
DEMOS_DIR = Path(__file__).parent.parent.parent
CONFIGS_DIR = DEMOS_DIR / "configs"
PLAYWRIGHT_DIR = DEMOS_DIR / "playwright"
OUTPUT_DIR = DEMOS_DIR / "output"
ASSETS_DIR = DEMOS_DIR / "assets"
CACHE_DIR = DEMOS_DIR / ".cache"


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Demo Generator - Create promotional videos from Open Privacy Suite."""
    pass


@cli.command()
@click.argument("config_name")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--skip-recording", is_flag=True, help="Skip recording, use existing video")
@click.option("--skip-tts", is_flag=True, help="Skip TTS generation")
@click.option("--skip-clips", is_flag=True, help="Skip clip extraction")
@click.option("--skip-copy", is_flag=True, help="Skip copy generation")
def generate(config_name: str, output: str | None, skip_recording: bool, skip_tts: bool, skip_clips: bool, skip_copy: bool):
    """Generate a complete demo video with all assets."""
    config_path = _resolve_config(config_name)
    config = load_config(config_path)

    output_dir = Path(output) if output else OUTPUT_DIR / config.name
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold blue]Generating demo:[/] {config.title}")
    console.print(f"[dim]Output: {output_dir}[/]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Step 1: Generate Playwright spec and record
        if not skip_recording:
            task = progress.add_task("Recording video...", total=None)
            video_path = _run_recording(config, output_dir)
            progress.update(task, completed=True)
        else:
            video_path = output_dir / f"{config.name}_raw.webm"
            if not video_path.exists():
                console.print(f"[red]Error: No existing video at {video_path}[/]")
                raise click.Abort()

        # Step 2: Generate TTS narration
        if not skip_tts:
            task = progress.add_task("Generating narration...", total=None)
            narrations = config.get_narrations()
            audio_segments = _generate_tts(narrations, config)
            progress.update(task, completed=True)
        else:
            audio_segments = []

        # Step 3: Load timings and generate captions
        task = progress.add_task("Generating captions...", total=None)
        timings_path = output_dir / f"{config.name}_timings.json"
        step_timings = json.loads(timings_path.read_text()) if timings_path.exists() else {}
        resolution = (config.video.resolution.width, config.video.resolution.height)
        captions_path = _generate_captions(
            audio_segments,
            step_timings.get("steps", {}),
            output_dir / "captions.ass",
            resolution=resolution,
        )
        progress.update(task, completed=True)

        # Step 4: Compose final video
        task = progress.add_task("Composing video...", total=None)
        master_path = _compose_video(
            video_path,
            audio_segments,
            step_timings.get("steps", {}),
            captions_path,
            output_dir / f"{config.name}.mp4",
            config,
        )
        progress.update(task, completed=True)

        # Step 5: Extract clips
        if not skip_clips:
            task = progress.add_task("Extracting clips...", total=None)
            clips = _extract_clips(master_path, output_dir / "clips", audio_segments)
            progress.update(task, completed=True)
        else:
            clips = []

        # Step 6: Export to platforms
        if clips:
            task = progress.add_task("Exporting to platforms...", total=None)
            _export_platforms(clips, output_dir / "clips", captions_path)
            progress.update(task, completed=True)

        # Step 7: Generate copy
        if clips and not skip_copy:
            task = progress.add_task("Generating copy...", total=None)
            _generate_copy(clips, config, output_dir / "clips")
            progress.update(task, completed=True)

    console.print(f"\n[bold green]Done![/] Output saved to {output_dir}")
    console.print(f"  Master video: {master_path}")
    if clips:
        console.print(f"  Clips: {len(clips)} extracted")


@cli.command()
@click.argument("config_name")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
def record(config_name: str, output: str | None):
    """Record video only (no processing)."""
    config_path = _resolve_config(config_name)
    config = load_config(config_path)

    output_dir = Path(output) if output else OUTPUT_DIR / config.name
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold blue]Recording demo:[/] {config.title}")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Recording video...", total=None)
        video_path = _run_recording(config, output_dir)
        progress.update(task, completed=True)

    console.print(f"\n[bold green]Done![/] Video saved to {video_path}")


@cli.command()
@click.argument("config_name")
@click.option("--video", "-v", type=click.Path(exists=True), help="Existing video to process")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
def process(config_name: str, video: str | None, output: str | None):
    """Process an existing video (TTS, captions, composition)."""
    config_path = _resolve_config(config_name)
    config = load_config(config_path)

    output_dir = Path(output) if output else OUTPUT_DIR / config.name
    output_dir.mkdir(parents=True, exist_ok=True)

    video_path = Path(video) if video else output_dir / f"{config.name}_raw.webm"
    if not video_path.exists():
        console.print(f"[red]Error: Video not found at {video_path}[/]")
        raise click.Abort()

    console.print(f"[bold blue]Processing video:[/] {video_path}")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Generate TTS
        task = progress.add_task("Generating narration...", total=None)
        narrations = config.get_narrations()
        audio_segments = _generate_tts(narrations, config)
        progress.update(task, completed=True)

        # Load timings
        timings_path = output_dir / f"{config.name}_timings.json"
        step_timings = json.loads(timings_path.read_text()) if timings_path.exists() else {}

        # Generate captions
        task = progress.add_task("Generating captions...", total=None)
        resolution = (config.video.resolution.width, config.video.resolution.height)
        captions_path = _generate_captions(
            audio_segments,
            step_timings.get("steps", {}),
            output_dir / "captions.ass",
            resolution=resolution,
        )
        progress.update(task, completed=True)

        # Compose video
        task = progress.add_task("Composing video...", total=None)
        master_path = _compose_video(
            video_path,
            audio_segments,
            step_timings.get("steps", {}),
            captions_path,
            output_dir / f"{config.name}.mp4",
            config,
        )
        progress.update(task, completed=True)

    console.print(f"\n[bold green]Done![/] Output saved to {master_path}")


@cli.command()
@click.argument("video", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--count", "-n", default=10, help="Number of clips to extract")
@click.option("--min-duration", default=15.0, help="Minimum clip duration (seconds)")
@click.option("--max-duration", default=60.0, help="Maximum clip duration (seconds)")
def clip(video: str, output: str | None, count: int, min_duration: float, max_duration: float):
    """Extract clips from a video."""
    video_path = Path(video)
    output_dir = Path(output) if output else video_path.parent / "clips"
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold blue]Extracting clips from:[/] {video_path}")

    config = ClippingConfig(
        min_duration=min_duration,
        max_duration=max_duration,
        target_count=count,
    )
    clipper = SceneClipper(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Detecting scenes...", total=None)
        clips = clipper.extract_clips(video_path, output_dir)
        progress.update(task, completed=True)

    console.print(f"\n[bold green]Done![/] Extracted {len(clips)} clips to {output_dir}")
    for c in clips:
        console.print(f"  {c.id}: {c.duration:.1f}s (score: {c.score:.2f})")


@cli.command("list")
def list_configs():
    """List available demo configurations."""
    console.print("[bold]Available demo configurations:[/]")
    for config_file in CONFIGS_DIR.glob("*.yaml"):
        try:
            config = load_config(config_file)
            console.print(f"  [cyan]{config_file.stem}[/] - {config.title}")
        except Exception as e:
            console.print(f"  [red]{config_file.stem}[/] - Error: {e}")


def _resolve_config(name: str) -> Path:
    """Resolve config name to path."""
    if Path(name).exists():
        return Path(name)

    config_path = CONFIGS_DIR / f"{name}.yaml"
    if config_path.exists():
        return config_path

    raise click.BadParameter(f"Config not found: {name}")


def _run_recording(config, output_dir: Path) -> Path:
    """Run Playwright recording."""
    # Generate spec
    spec_gen = SpecGenerator(PLAYWRIGHT_DIR / "tests" / "generated")
    spec_path = spec_gen.generate(config)

    # Run recording
    runner = PlaywrightRunner(PLAYWRIGHT_DIR, output_dir)
    result = runner.run(config, spec_path)

    if not result.success:
        console.print(f"[red]Recording failed: {result.error}[/]")
        raise click.Abort()

    return result.video_path


def _generate_tts(narrations: list[tuple[str, str]], config) -> list:
    """Generate TTS audio segments."""
    if not narrations:
        return []

    tts_config = TTSConfig(
        voice=config.voice.voice_id,
        speed=config.voice.speed,
    )

    processor = TTSProcessor(CACHE_DIR / "tts")
    return processor.generate_narration(narrations, tts_config)


def _generate_captions(
    audio_segments: list,
    step_timings: dict,
    output_path: Path,
    resolution: tuple[int, int] = (1920, 1080),
) -> Path:
    """Generate caption file with resolution-aware styling."""
    generator = CaptionGenerator()
    return generator.generate_from_segments(
        audio_segments,
        step_timings,
        output_path,
        format="ass",
        resolution=resolution,
    )


def _compose_video(
    video_path: Path,
    audio_segments: list,
    step_timings: dict,
    captions_path: Path,
    output_path: Path,
    config,
) -> Path:
    """Compose final video with audio, captions, and branding."""
    # Build composition config from demo config quality settings
    quality = config.video.quality
    composition_config = CompositionConfig(
        resolution=(config.video.resolution.width, config.video.resolution.height),
        fps=config.video.fps,
        preset=quality.preset,
        crf=quality.crf,
        video_bitrate=quality.bitrate,
        audio_bitrate=quality.audio_bitrate,
        profile=quality.profile,
        level=quality.level,
    )

    processor = FFmpegProcessor(composition_config)

    # Check for branding assets
    watermark = None
    logo_path = ASSETS_DIR / "branding" / "logo.png"
    if logo_path.exists():
        watermark = WatermarkConfig(
            path=logo_path,
            position=config.branding.watermark.position,
            opacity=config.branding.watermark.opacity,
        )

    intro_path = ASSETS_DIR / "branding" / "intro.mp4"
    outro_path = ASSETS_DIR / "branding" / "outro.mp4"

    return processor.compose_demo(
        video_path,
        audio_segments,
        step_timings,
        output_path,
        captions_path=captions_path,
        watermark=watermark,
        intro_path=intro_path if intro_path.exists() else None,
        outro_path=outro_path if outro_path.exists() else None,
    )


def _extract_clips(video_path: Path, output_dir: Path, audio_segments: list) -> list:
    """Extract clips from master video."""
    # Get narration boundaries for clip alignment
    boundaries = None
    if audio_segments:
        boundaries = [(0, seg.duration) for seg in audio_segments]

    clipper = SceneClipper()
    return clipper.extract_clips(video_path, output_dir, boundaries)


def _export_platforms(clips: list, output_dir: Path, captions_path: Path):
    """Export clips to compatible platforms (16:9 only for landscape source)."""
    exporter = PlatformExporter(output_dir)
    # Only export to 16:9 platforms since our source is landscape
    # Portrait platforms (tiktok, reels, shorts) need special handling
    platforms = ["twitter", "youtube"]
    for clip in clips:
        exporter.export_all_platforms(clip, platforms=platforms, captions_path=captions_path)


def _generate_copy(clips: list, config, output_dir: Path):
    """Generate social media copy for clips."""
    try:
        generator = CopyGenerator(CopyConfig(
            product_name="Open Privacy Suite",
            product_tagline=config.metadata.description or "Privacy-first blockchain access",
        ))

        for clip in clips:
            copy = generator.generate_copy(
                clip.id,
                f"Clip from {config.title} ({clip.duration:.0f}s)",
                config.total_narration_text(),
            )
            generator.write_copy_file(copy, output_dir / clip.id)
    except ValueError:
        console.print("[yellow]Skipping copy generation (ANTHROPIC_API_KEY not set)[/]")


if __name__ == "__main__":
    cli()
