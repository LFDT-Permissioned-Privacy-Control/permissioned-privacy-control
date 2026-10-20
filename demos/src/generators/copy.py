"""Claude API integration for generating social media copy."""

import os
from dataclasses import dataclass
from pathlib import Path

import httpx


@dataclass
class CopyConfig:
    """Configuration for copy generation."""

    brand_voice: str = "professional, innovative, privacy-focused"
    target_audience: str = "developers, Web3 builders, privacy advocates"
    product_name: str = "Open Privacy Suite"
    product_tagline: str = "Privacy-first blockchain access"


@dataclass
class PlatformCopy:
    """Generated copy for a specific platform."""

    platform: str
    caption: str
    hashtags: list[str]
    cta: str
    char_count: int


@dataclass
class ClipCopy:
    """All generated copy for a clip."""

    clip_id: str
    description: str
    platforms: dict[str, PlatformCopy]


class CopyGenerator:
    """Generates social media copy using Claude API."""

    PLATFORM_SPECS = {
        "tiktok": {
            "max_chars": 2200,
            "hashtag_count": 5,
            "tone": "engaging, trendy, energetic",
            "cta_style": "direct action",
        },
        "reels": {
            "max_chars": 2200,
            "hashtag_count": 30,
            "tone": "visual, aspirational",
            "cta_style": "soft suggestion",
        },
        "shorts": {
            "max_chars": 100,
            "hashtag_count": 3,
            "tone": "informative, concise",
            "cta_style": "subscribe/learn more",
        },
        "linkedin": {
            "max_chars": 3000,
            "hashtag_count": 5,
            "tone": "professional, thought-leadership",
            "cta_style": "professional engagement",
        },
        "twitter": {
            "max_chars": 280,
            "hashtag_count": 2,
            "tone": "punchy, clever",
            "cta_style": "engagement question",
        },
    }

    def __init__(self, config: CopyConfig | None = None, api_key: str | None = None):
        self.config = config or CopyConfig()
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")

    def generate_copy(
        self,
        clip_id: str,
        clip_description: str,
        narration_text: str,
        platforms: list[str] | None = None,
    ) -> ClipCopy:
        """Generate copy for a clip across multiple platforms."""
        platforms = platforms or list(self.PLATFORM_SPECS.keys())

        # Generate platform-specific copy
        platform_copy = {}
        for platform in platforms:
            if platform not in self.PLATFORM_SPECS:
                continue

            copy = self._generate_platform_copy(
                platform, clip_description, narration_text
            )
            platform_copy[platform] = copy

        return ClipCopy(
            clip_id=clip_id,
            description=clip_description,
            platforms=platform_copy,
        )

    def _generate_platform_copy(
        self,
        platform: str,
        clip_description: str,
        narration_text: str,
    ) -> PlatformCopy:
        """Generate copy for a specific platform."""
        specs = self.PLATFORM_SPECS[platform]

        prompt = f"""Generate social media copy for a {platform} post about this video clip.

PRODUCT: {self.config.product_name}
TAGLINE: {self.config.product_tagline}
BRAND VOICE: {self.config.brand_voice}
TARGET AUDIENCE: {self.config.target_audience}

VIDEO DESCRIPTION: {clip_description}
NARRATION/TRANSCRIPT: {narration_text}

PLATFORM REQUIREMENTS:
- Platform: {platform}
- Max characters: {specs['max_chars']}
- Tone: {specs['tone']}
- Hashtag count: {specs['hashtag_count']}
- CTA style: {specs['cta_style']}

Generate:
1. CAPTION: A compelling caption that fits the platform's character limit and tone
2. HASHTAGS: Exactly {specs['hashtag_count']} relevant hashtags (without # symbol)
3. CTA: A call-to-action appropriate for the platform

Format your response EXACTLY like this (no markdown, no extra formatting):
CAPTION: [your caption here]
HASHTAGS: tag1, tag2, tag3
CTA: [your call to action]
"""

        response = self._call_api(prompt)
        return self._parse_response(platform, response, specs)

    def _call_api(self, prompt: str) -> str:
        """Call Claude API."""
        with httpx.Client(timeout=60.0) as client:
            response = client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-3-5-sonnet-20241022",
                    "max_tokens": 1024,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ],
                },
            )
            response.raise_for_status()
            data = response.json()
            return data["content"][0]["text"]

    def _parse_response(
        self, platform: str, response: str, specs: dict
    ) -> PlatformCopy:
        """Parse API response into structured copy."""
        lines = response.strip().split("\n")

        caption = ""
        hashtags = []
        cta = ""

        for line in lines:
            line = line.strip()
            if line.startswith("CAPTION:"):
                caption = line.replace("CAPTION:", "").strip()
            elif line.startswith("HASHTAGS:"):
                tags_str = line.replace("HASHTAGS:", "").strip()
                hashtags = [t.strip().lstrip("#") for t in tags_str.split(",")]
            elif line.startswith("CTA:"):
                cta = line.replace("CTA:", "").strip()

        # Truncate caption if needed
        if len(caption) > specs["max_chars"]:
            caption = caption[: specs["max_chars"] - 3] + "..."

        return PlatformCopy(
            platform=platform,
            caption=caption,
            hashtags=hashtags[: specs["hashtag_count"]],
            cta=cta,
            char_count=len(caption),
        )

    def write_copy_file(self, copy: ClipCopy, output_dir: Path) -> Path:
        """Write copy to markdown file."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        content = [f"# Copy for {copy.clip_id}\n"]
        content.append(f"**Description:** {copy.description}\n")

        for platform, pc in copy.platforms.items():
            content.append(f"\n## {platform.title()}\n")
            content.append(f"**Caption ({pc.char_count} chars):**\n")
            content.append(f"{pc.caption}\n")
            content.append(f"\n**Hashtags:**\n")
            content.append(" ".join(f"#{tag}" for tag in pc.hashtags))
            content.append(f"\n\n**CTA:** {pc.cta}\n")

        output_path = output_dir / f"{copy.clip_id}_copy.md"
        output_path.write_text("\n".join(content))
        return output_path


def generate_copy(
    clip_id: str,
    clip_description: str,
    narration_text: str,
    platforms: list[str] | None = None,
    config: CopyConfig | None = None,
) -> ClipCopy:
    """Convenience function for generating copy."""
    generator = CopyGenerator(config)
    return generator.generate_copy(clip_id, clip_description, narration_text, platforms)
