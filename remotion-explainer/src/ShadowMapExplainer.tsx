import React from 'react';
import {
  AbsoluteFill,
  Easing,
  Sequence,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from 'remotion';

type SceneCardProps = {
  title: string;
  subtitle: string;
  bullets: string[];
  accent: string;
};

const container: React.CSSProperties = {
  background:
    'radial-gradient(circle at 10% 15%, rgba(34, 197, 94, 0.28), rgba(10, 20, 34, 0.95) 45%), linear-gradient(135deg, #0f172a, #020617)',
  color: '#e2e8f0',
  fontFamily: 'Inter, ui-sans-serif, system-ui',
};

const SceneCard: React.FC<SceneCardProps> = ({title, subtitle, bullets, accent}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();

  const rise = spring({
    fps,
    frame,
    config: {
      damping: 18,
      stiffness: 120,
      mass: 0.9,
    },
  });

  const fade = interpolate(frame, [0, 25], [0, 1], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
    easing: Easing.out(Easing.cubic),
  });

  return (
    <AbsoluteFill style={{...container, padding: 120}}>
      <div
        style={{
          transform: `translateY(${interpolate(rise, [0, 1], [30, 0])}px)`,
          opacity: fade,
          border: `1px solid ${accent}`,
          borderRadius: 28,
          background: 'rgba(15, 23, 42, 0.6)',
          backdropFilter: 'blur(6px)',
          padding: '56px 64px',
          boxShadow: `0 20px 55px ${accent}40`,
        }}
      >
        <p
          style={{
            color: accent,
            textTransform: 'uppercase',
            letterSpacing: '0.18em',
            fontWeight: 700,
            margin: 0,
          }}
        >
          Enterprise tech explainer
        </p>
        <h1 style={{fontSize: 72, margin: '20px 0 14px', lineHeight: 1.1}}>{title}</h1>
        <p style={{fontSize: 34, lineHeight: 1.4, marginTop: 0, color: '#cbd5e1'}}>{subtitle}</p>
        <ul style={{marginTop: 28, display: 'grid', rowGap: 18, fontSize: 30, paddingLeft: 28}}>
          {bullets.map((bullet) => (
            <li key={bullet}>{bullet}</li>
          ))}
        </ul>
      </div>
    </AbsoluteFill>
  );
};

export const ShadowMapTechExplainer: React.FC = () => {
  return (
    <AbsoluteFill>
      <Sequence from={0} durationInFrames={220}>
        <SceneCard
          title="ShadowMap in 30 seconds"
          subtitle="Start with first principles: map assets, verify risk, then act with proof."
          accent="#22d3ee"
          bullets={[
            'Observe all exposed internet-facing assets.',
            'Separate signal from noise using reproducible checks.',
            'Deliver executive-grade evidence with confidence.',
          ]}
        />
      </Sequence>
      <Sequence from={220} durationInFrames={230}>
        <SceneCard
          title="How the engine works"
          subtitle="Motion mirrors the pipeline: discovery → enrichment → reporting."
          accent="#38bdf8"
          bullets={[
            'Discovery: enumerate subdomains and exposed services.',
            'Enrichment: fingerprint technologies and security posture.',
            'Reporting: summarize risk for analysts and leadership.',
          ]}
        />
      </Sequence>
      <Sequence from={450} durationInFrames={230}>
        <SceneCard
          title="Enterprise operating model"
          subtitle="Treat security as a system, not a one-off scan."
          accent="#14b8a6"
          bullets={[
            'Automate scans in CI for consistent coverage.',
            'Attach SBOM and provenance for auditability.',
            'Track trends over time to prioritize remediation.',
          ]}
        />
      </Sequence>
      <Sequence from={680} durationInFrames={220}>
        <SceneCard
          title="Call to action"
          subtitle="Render, narrate, and ship to stakeholders in a single flow."
          accent="#2dd4bf"
          bullets={[
            'Open Remotion Studio for timing + typography polish.',
            'Record voiceover aligned with each decision point.',
            'Render mp4 and distribute in internal comms channels.',
          ]}
        />
      </Sequence>
    </AbsoluteFill>
  );
};
