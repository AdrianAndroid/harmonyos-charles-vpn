import { common } from '@kit.AbilityKit';
import { BuilderNode, FrameNode, NodeController, PiPWindow, typeNode, UIContext } from '@kit.ArkUI';

export class PipFlowRow {
  method: string = '';
  host: string = '';
  path: string = '';
  statusCode: string = '';
  sizeText: string = '';
  active: boolean = false;
}

export class PipParams {
  running: boolean = false;
  total: number = 0;
  active: number = 0;
  downText: string = '0 B';
  upText: string = '0 B';
  rows: PipFlowRow[] = [];
}

const PIP_COLOR_BG: string = '#F0101014';
const PIP_COLOR_TEXT: string = '#FFF2F2F7';
const PIP_COLOR_SUB: string = '#FF8E8E93';
const PIP_COLOR_FAINT: string = '#FFAEAEB2';
const PIP_COLOR_GREEN: string = '#FF34C759';
const PIP_COLOR_BLUE: string = '#FF0A84FF';
const PIP_COLOR_RED: string = '#FFFF453A';
const PIP_COLOR_ORANGE: string = '#FFFF9F0A';

function pipStatusColor(code: string): string {
  if (code.startsWith('2')) {
    return PIP_COLOR_GREEN;
  }
  if (code.startsWith('3')) {
    return PIP_COLOR_BLUE;
  }
  if (code.startsWith('4')) {
    return PIP_COLOR_ORANGE;
  }
  if (code.startsWith('5')) {
    return PIP_COLOR_RED;
  }
  return PIP_COLOR_FAINT;
}

@Builder
function buildPipPanel(params: PipParams) {
  Column() {
    Row({ space: 6 }) {
      Circle()
        .width(7)
        .height(7)
        .fill(params.running ? PIP_COLOR_GREEN : PIP_COLOR_SUB)
      Text('流量')
        .fontSize(13)
        .fontWeight(FontWeight.Bold)
        .fontColor(PIP_COLOR_TEXT)
        .layoutWeight(1)
      Text(`↓ ${params.downText}  ↑ ${params.upText}`)
        .fontSize(10)
        .fontColor(PIP_COLOR_FAINT)
    }
    .width('100%')
    .padding({ left: 12, right: 12, top: 10, bottom: 8 })

    Divider().color('#22FFFFFF')

    if (params.rows.length === 0) {
      Column() {
        Text('暂无 HTTP 流量')
          .fontSize(12)
          .fontColor(PIP_COLOR_SUB)
      }
      .width('100%')
      .layoutWeight(1)
      .justifyContent(FlexAlign.Center)
    } else {
      Column({ space: 2 }) {
        ForEach(params.rows, (row: PipFlowRow) => {
          Column({ space: 3 }) {
            Row({ space: 6 }) {
              Text(row.method)
                .fontSize(9)
                .fontWeight(FontWeight.Bold)
                .fontColor(PIP_COLOR_BLUE)
              Text(row.host)
                .fontSize(11)
                .fontColor(PIP_COLOR_TEXT)
                .layoutWeight(1)
                .maxLines(1)
                .textOverflow({ overflow: TextOverflow.Ellipsis })
              Circle()
                .width(5)
                .height(5)
                .fill(row.active ? PIP_COLOR_GREEN : PIP_COLOR_SUB)
            }
            .width('100%')

            Row({ space: 6 }) {
              Text(row.statusCode.length > 0 ? row.statusCode : '—')
                .fontSize(10)
                .fontColor(row.statusCode.length > 0 ? pipStatusColor(row.statusCode) : PIP_COLOR_SUB)
              Text(row.sizeText)
                .fontSize(10)
                .fontColor(PIP_COLOR_FAINT)
              Text(row.path.length > 0 ? row.path : '')
                .fontSize(10)
                .fontColor(PIP_COLOR_SUB)
                .layoutWeight(1)
                .maxLines(1)
                .textOverflow({ overflow: TextOverflow.Ellipsis })
            }
            .width('100%')
          }
          .width('100%')
          .padding({ left: 12, right: 12, top: 6, bottom: 6 })
        }, (row: PipFlowRow, index: number) =>
          `${index}_${row.method}_${row.host}_${row.path}_${row.statusCode}_${row.sizeText}_${row.active}`)
      }
      .width('100%')
      .padding({ top: 4 })
    }

    Blank()

    Divider().color('#22FFFFFF')

    Row() {
      Text(`共 ${params.total} 条 · 活动 ${params.active}`)
        .fontSize(10)
        .fontColor(PIP_COLOR_SUB)
    }
    .width('100%')
    .padding({ left: 12, right: 12, top: 8, bottom: 10 })
  }
  .width('100%')
  .height('100%')
  .backgroundColor(PIP_COLOR_BG)
  .borderRadius(14)
}

class PipPanelController extends NodeController {
  private node: BuilderNode<[PipParams]> | null = null;
  private params: PipParams = new PipParams();

  makeNode(context: UIContext): FrameNode | null {
    this.node = new BuilderNode<[PipParams]>(context);
    this.node.build(wrapBuilder<[PipParams]>(buildPipPanel), this.params);
    return this.node.getFrameNode();
  }

  update(params: PipParams): void {
    this.params = params;
    if (this.node !== null) {
      this.node.update(params);
    }
  }

  dispose(): void {
    if (this.node !== null) {
      this.node.dispose();
      this.node = null;
    }
  }
}

export class TrafficPip {
  private static instance: TrafficPip | undefined;
  private xController: XComponentController = new XComponentController();
  private panel: PipPanelController = new PipPanelController();
  private xNode: typeNode.XComponent | null = null;
  private pip: PiPWindow.PiPController | undefined = undefined;
  private active: boolean = false;
  private listener?: (active: boolean) => void;

  static shared(): TrafficPip {
    if (!TrafficPip.instance) {
      TrafficPip.instance = new TrafficPip();
    }
    return TrafficPip.instance;
  }

  setActiveListener(callback: (active: boolean) => void): void {
    this.listener = callback;
  }

  isSupported(): boolean {
    return PiPWindow.isPiPEnabled();
  }

  isActive(): boolean {
    return this.active;
  }

  async start(context: common.UIAbilityContext, uiContext: UIContext, params: PipParams): Promise<void> {
    this.panel.update(params);
    if (this.pip !== undefined) {
      await this.pip.startPiP();
      this.active = true;
      this.notify();
      return;
    }
    if (!PiPWindow.isPiPEnabled()) {
      throw new Error('当前设备不支持画中画');
    }
    if (this.xNode === null) {
      this.xNode = typeNode.createNode(uiContext, 'XComponent', {
        type: XComponentType.SURFACE,
        controller: this.xController
      });
    }
    const config: PiPWindow.PiPConfiguration = {
      context: context,
      componentController: this.xController,
      templateType: PiPWindow.PiPTemplateType.VIDEO_PLAY,
      contentWidth: 640,
      contentHeight: 800,
      customUIController: this.panel
    };
    const controller: PiPWindow.PiPController = await PiPWindow.create(config, this.xNode);
    this.pip = controller;
    controller.setAutoStartEnabled(false);
    controller.on('stateChange', (state: PiPWindow.PiPState) => {
      if (state === PiPWindow.PiPState.STOPPED) {
        this.teardown();
      }
    });
    await controller.startPiP();
    this.active = true;
    this.notify();
  }

  update(params: PipParams): void {
    if (!this.active) {
      return;
    }
    this.panel.update(params);
  }

  async stop(): Promise<void> {
    if (this.pip === undefined) {
      this.teardown();
      return;
    }
    try {
      await this.pip.stopPiP();
    } catch (_) {
      // 系统可能已自行结束画中画，这里只负责回收本地状态。
    }
    this.teardown();
  }

  private teardown(): void {
    const wasActive: boolean = this.active || this.pip !== undefined;
    this.active = false;
    this.pip = undefined;
    this.panel.dispose();
    this.xNode = null;
    if (wasActive) {
      this.notify();
    }
  }

  private notify(): void {
    if (this.listener) {
      this.listener(this.active);
    }
  }
}
