// SPDX-License-Identifier: AGPL-3.0-or-later
// Just enough of the `obsidian` module to load the plugin in Node and watch what it does.
export const notices: string[] = [];
export class Notice { constructor(msg: string) { notices.push(msg); } }
export class FileSystemAdapter { constructor(private base: string) {} getBasePath() { return this.base; } }
export class TFile { constructor(public path: string) {} }
class El {
  text = ""; classes: string[] = [];
  setText(t: string) { this.text = t; }
  addClass(c: string) { this.classes.push(c); }
  onClickEvent(_f: () => void) {}
  empty() {}
  createEl() { return new El(); }
}
export class Plugin {
  bars: El[] = []; commands: { id: string; callback: () => unknown }[] = [];
  private data: unknown = null;
  constructor(public app: any) {}
  addStatusBarItem() { const e = new El(); this.bars.push(e); return e; }
  addRibbonIcon() {}
  addCommand(c: { id: string; callback: () => unknown }) { this.commands.push(c); }
  addSettingTab() {}
  registerEvent() {}
  registerInterval(n: number) { return n; }
  async loadData() { return this.data; }
  async saveData(d: unknown) { this.data = d; }
}
export class PluginSettingTab { containerEl = new El(); constructor(public app: any, public plugin: any) {} }
export class Setting { constructor(_el: unknown) {} setName() { return this; } setDesc() { return this; } addText() { return this; } addToggle() { return this; } }
export type App = any;
