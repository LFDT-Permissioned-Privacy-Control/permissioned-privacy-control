"""Generate Playwright test specs from YAML demo configurations."""

import json
from pathlib import Path
from textwrap import dedent

from ..config.loader import DemoConfig, DemoStep


def _escape_selector(selector: str) -> str:
    """Escape a selector for use in JavaScript template literals."""
    # Use JSON encoding which handles all escaping properly
    return json.dumps(selector)


class SpecGenerator:
    """Converts YAML demo configs into executable Playwright test files."""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, config: DemoConfig) -> Path:
        """Generate a Playwright test file from a demo config."""
        spec_content = self._build_spec(config)
        output_path = self.output_dir / f"{config.name}.spec.ts"
        output_path.write_text(spec_content)
        return output_path

    def _build_spec(self, config: DemoConfig) -> str:
        """Build the complete test spec content."""
        imports = self._build_imports()
        setup = self._build_setup(config)
        steps = self._build_steps(config.steps)

        return f'''{imports}

{setup}

test("{config.title}", async ({{ page }}) => {{
  // Inject mock wallet for Web3 interactions
  await injectMockWallet(page);

  // Track step timings for narration sync
  const stepTimings: Record<string, {{ start: number; end: number }}> = {{}};
  const startTime = Date.now();

{steps}

  // Save step timings for post-processing
  const timingsPath = `${{process.cwd()}}/test-results/{config.name}-timings.json`;
  const fs = await import("fs");
  fs.writeFileSync(timingsPath, JSON.stringify({{
    steps: stepTimings,
    totalDuration: Date.now() - startTime,
  }}, null, 2));
}});
'''

    def _build_imports(self) -> str:
        return dedent('''
            import { test, expect } from "@playwright/test";
            import { injectMockWallet } from "../../helpers/mock-wallet";
        ''').strip()

    def _build_setup(self, config: DemoConfig) -> str:
        vw = config.video.viewport.width
        vh = config.video.viewport.height
        return dedent(f'''
            test.use({{
              viewport: {{ width: {vw}, height: {vh} }},
              video: {{
                mode: "on",
                size: {{ width: {config.video.resolution.width}, height: {config.video.resolution.height} }},
              }},
            }});
        ''').strip()

    def _build_steps(self, steps: list[DemoStep]) -> str:
        """Build all step code blocks."""
        step_blocks = []
        for step in steps:
            block = self._build_step(step)
            step_blocks.append(block)
        return "\n\n".join(step_blocks)

    def _build_step(self, step: DemoStep) -> str:
        """Build code for a single step."""
        lines = [
            f'  // Step: {step.id}',
            f'  stepTimings["{step.id}"] = {{ start: Date.now() - startTime, end: 0 }};',
        ]

        # Add action based on type
        action_code = self._get_action_code(step)
        lines.extend(f"  {line}" for line in action_code.split("\n") if line.strip())

        # Add wait condition if specified
        if step.wait:
            wait_code = self._get_wait_code(step)
            lines.extend(f"  {line}" for line in wait_code.split("\n") if line.strip())

        # Add pause if specified
        if step.pause > 0:
            lines.append(f"  await page.waitForTimeout({int(step.pause * 1000)});")

        # Add screenshot if requested
        if step.screenshot:
            lines.append(f'  await page.screenshot({{ path: `test-results/{step.id}.png`, fullPage: false }});')

        # Record end time
        lines.append(f'  stepTimings["{step.id}"].end = Date.now() - startTime;')

        return "\n".join(lines)

    def _get_action_code(self, step: DemoStep) -> str:
        """Generate action code based on step type."""
        match step.action:
            case "navigate":
                return f'await page.goto({_escape_selector(step.url)});'

            case "click":
                return f'await page.click({_escape_selector(step.selector)});'

            case "fill":
                return f'await page.fill({_escape_selector(step.selector)}, {_escape_selector(step.value)});'

            case "type":
                return f'await page.type({_escape_selector(step.selector)}, {_escape_selector(step.value)}, {{ delay: 50 }});'

            case "hover":
                return f'await page.hover({_escape_selector(step.selector)});'

            case "scroll":
                if step.selector:
                    return f'await page.locator({_escape_selector(step.selector)}).scrollIntoViewIfNeeded();'
                return 'await page.evaluate(() => window.scrollBy(0, 300));'

            case "wait":
                return f"await page.waitForTimeout({int((step.pause or 1) * 1000)});"

            case "screenshot":
                return f'await page.screenshot({{ path: `test-results/{step.id}.png` }});'

            case _:
                return f'// Unknown action: {step.action}'

    def _get_wait_code(self, step: DemoStep) -> str:
        """Generate wait condition code."""
        if not step.wait:
            return ""

        lines = []
        if step.wait.selector:
            timeout = step.wait.timeout
            lines.append(
                f'await page.waitForSelector({_escape_selector(step.wait.selector)}, {{ timeout: {timeout} }});'
            )
        if step.wait.navigation:
            lines.append(
                f'await page.waitForURL({_escape_selector("**" + step.wait.navigation + "**")}, {{ timeout: {step.wait.timeout} }});'
            )

        return "\n".join(lines)


def generate_spec(config: DemoConfig, output_dir: str | Path) -> Path:
    """Convenience function to generate a spec file."""
    generator = SpecGenerator(Path(output_dir))
    return generator.generate(config)
