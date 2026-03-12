import {Composition} from 'remotion';
import {ShadowMapTechExplainer} from './ShadowMapExplainer';

export const RemotionRoot = () => {
  return (
    <Composition
      id="ShadowMapTechExplainer"
      component={ShadowMapTechExplainer}
      durationInFrames={900}
      fps={30}
      width={1920}
      height={1080}
    />
  );
};
