# ShadowMap Tech Explainer (Remotion)

This workspace gives you an enterprise-style motion design baseline for a technical explainer video.

## Why this structure

Built from first principles:

1. **Problem framing**: One scene per decision layer (what, how, operate, next step).
2. **Narrative coherence**: Each scene has one headline, one subtitle, and exactly three supporting bullets.
3. **Production rigor**: All motion and typography live in source control for repeatable rendering.

## Quick start (Yarn 4 Berry)

```bash
cd remotion-explainer
yarn set version 4.4.1
yarn install
yarn dev
```

Then render production output:

```bash
yarn render
```

Output file:

- `out/shadowmap-tech-explainer.mp4`

## Test + download checklist

Use this when you want a rigorous "does it work and can I deliver it" validation.

```bash
cd remotion-explainer
yarn test:video
```

The command runs three quality gates:

1. **Build gate** (`yarn build`) → validates composition code and bundling.
2. **Render gate** (`yarn render`) → validates runtime rendering.
3. **Delivery gate** (file check + sha256) → proves the final MP4 exists and is ready to share.

If rendering fails because Chrome Headless Shell cannot be downloaded in your environment, point Remotion to a local browser:

```bash
export REMOTION_CHROME_EXECUTABLE=/path/to/chrome-or-chromium
yarn test:video
```

### How to download/share the generated video

After a successful run, use one of these delivery options:

- Copy directly from: `remotion-explainer/out/shadowmap-tech-explainer.mp4`
- Serve for browser download:

```bash
cd remotion-explainer/out
python -m http.server 8080
```

Then open `http://localhost:8080/shadowmap-tech-explainer.mp4` and save the file.

## Storyboard map

- **Scene 1**: Value proposition in executive language.
- **Scene 2**: Architecture and data flow.
- **Scene 3**: Enterprise operations and governance.
- **Scene 4**: Call to action with adoption path.

## Next upgrades

- Add voiceover timing markers with frame-level notes.
- Add brand tokens (font, color, iconography) from design system.
- Add data-driven animated charts from real ShadowMap scan exports.
