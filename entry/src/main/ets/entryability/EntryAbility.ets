import { UIAbility } from '@kit.AbilityKit';
import { window } from '@kit.ArkUI';

export default class EntryAbility extends UIAbility {
  onWindowStageCreate(stage: window.WindowStage): void {
    try {
      stage.loadContent('pages/Index', (error) => {
        if (error.code) {
          console.error(`Failed to load Index: ${error.message}`);
        }
      });
    } catch (error) {
      console.error(`Unable to create main window: ${JSON.stringify(error)}`);
    }
  }
}
