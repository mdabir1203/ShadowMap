# Enterprise Tech Explainer Blueprint (Remotion)

Use this when you need a rigorous, enterprise-grade explainer for how ShadowMap works.

## First-principles narrative model

1. **Observation layer** – What is happening in the external attack surface?
2. **Inference layer** – What does the data imply about risk?
3. **Decision layer** – What should an enterprise do next?

If a scene does not support one of the three layers, cut it.

## Mental models to enforce coherence

- **OODA loop** (Observe, Orient, Decide, Act): each scene should map to one or more OODA stages.
- **Signal vs. noise**: every visual element must either clarify risk or be removed.
- **Systems thinking**: present scanning as part of continuous governance, not a one-time task.

## Implementation in this repository

The `remotion-explainer/` project includes:

- A `ShadowMapTechExplainer` composition at 1920x1080, 30fps.
- Four sequenced scenes using enterprise visual language and concise copy.
- Source-controlled animation primitives (`spring`, `interpolate`) for reproducibility.

## Production checklist

- Validate copy with security + executive stakeholders.
- Align brand styles (font, color, motion speed).
- Pair each scene with voiceover line and on-screen caption.
- Render draft MP4, collect feedback, iterate, and final render.


## Verification and artifact handoff

- Run `cd remotion-explainer && yarn test:video` before stakeholder review.
- Confirm the SHA256 digest output so distribution teams can verify integrity.
- Share `remotion-explainer/out/shadowmap-tech-explainer.mp4` directly, or host `remotion-explainer/out/` via `python -m http.server` for browser-based download.
