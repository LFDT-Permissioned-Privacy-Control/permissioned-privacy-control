"""YAML configuration loader for demo specs."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Resolution:
    width: int
    height: int


@dataclass
class QualityConfig:
    """Video encoding quality settings."""
    preset: str = "slow"  # ultrafast, superfast, veryfast, faster, fast, medium, slow, slower, veryslow
    crf: int = 15  # 0-51, lower = higher quality (15-18 is near-lossless)
    bitrate: str = "25M"  # Target bitrate
    audio_bitrate: str = "320k"
    profile: str = "high"  # baseline, main, high
    level: str = "4.2"


@dataclass
class VideoConfig:
    resolution: Resolution
    fps: int = 60
    viewport: Resolution = None
    quality: QualityConfig = None

    def __post_init__(self):
        if self.viewport is None:
            self.viewport = Resolution(width=1280, height=720)
        if self.quality is None:
            self.quality = QualityConfig()


@dataclass
class VoiceConfig:
    provider: str = "openai"
    voice_id: str = "alloy"
    speed: float = 1.0


@dataclass
class WaitCondition:
    selector: str | None = None
    navigation: str | None = None
    timeout: int = 30000


@dataclass
class DemoStep:
    id: str
    action: str
    narration: str = ""
    url: str | None = None
    selector: str | None = None
    value: str | None = None
    wait: WaitCondition | None = None
    screenshot: bool = False
    pause: float = 0.0

    @classmethod
    def from_dict(cls, data: dict) -> "DemoStep":
        wait_data = data.pop("wait", None)
        wait = None
        if wait_data:
            wait = WaitCondition(**wait_data)
        return cls(wait=wait, **data)


@dataclass
class WatermarkConfig:
    position: str = "bottom-right"
    opacity: float = 0.7


@dataclass
class IntroConfig:
    duration: float = 3.0


@dataclass
class OutroConfig:
    cta: str = ""
    duration: float = 4.0


@dataclass
class BrandingConfig:
    watermark: WatermarkConfig = field(default_factory=WatermarkConfig)
    intro: IntroConfig = field(default_factory=IntroConfig)
    outro: OutroConfig = field(default_factory=OutroConfig)

    @classmethod
    def from_dict(cls, data: dict | None) -> "BrandingConfig":
        if not data:
            return cls()
        return cls(
            watermark=WatermarkConfig(**data.get("watermark", {})),
            intro=IntroConfig(**data.get("intro", {})),
            outro=OutroConfig(**data.get("outro", {})),
        )


@dataclass
class CaptionsConfig:
    style: str = "modern"
    position: str = "bottom"
    font_size: int = 48
    font_color: str = "white"
    outline_color: str = "black"
    outline_width: int = 2


@dataclass
class ExportFormat:
    aspect: str
    resolution: str
    suffix: str = ""


@dataclass
class Metadata:
    name: str
    title: str
    description: str = ""


@dataclass
class DemoConfig:
    version: str
    metadata: Metadata
    video: VideoConfig
    voice: VoiceConfig
    steps: list[DemoStep]
    branding: BrandingConfig
    captions: CaptionsConfig
    export: list[ExportFormat]

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def title(self) -> str:
        return self.metadata.title

    def get_narrations(self) -> list[tuple[str, str]]:
        """Return list of (step_id, narration) tuples for steps with narration."""
        return [(s.id, s.narration) for s in self.steps if s.narration]

    def total_narration_text(self) -> str:
        """Return all narration text concatenated."""
        return " ".join(s.narration for s in self.steps if s.narration)


def load_config(path: str | Path) -> DemoConfig:
    """Load and parse a demo configuration from YAML file."""
    path = Path(path)
    with open(path) as f:
        data = yaml.safe_load(f)

    # Parse metadata
    metadata = Metadata(**data["metadata"])

    # Parse video config
    video_data = data["video"]
    quality_data = video_data.get("quality", {})
    video = VideoConfig(
        resolution=Resolution(**video_data["resolution"]),
        fps=video_data.get("fps", 60),
        viewport=Resolution(**video_data.get("viewport", {"width": 1280, "height": 720})),
        quality=QualityConfig(**quality_data) if quality_data else QualityConfig(),
    )

    # Parse voice config
    voice = VoiceConfig(**data.get("voice", {}))

    # Parse steps
    steps = [DemoStep.from_dict(s.copy()) for s in data["steps"]]

    # Parse branding
    branding = BrandingConfig.from_dict(data.get("branding"))

    # Parse captions
    captions = CaptionsConfig(**data.get("captions", {}))

    # Parse export formats
    export = [ExportFormat(**e) for e in data.get("export", [])]

    return DemoConfig(
        version=data["version"],
        metadata=metadata,
        video=video,
        voice=voice,
        steps=steps,
        branding=branding,
        captions=captions,
        export=export,
    )
