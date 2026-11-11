// SPDX-License-Identifier: AGPL-3.0-or-later
// tgsync for Obsidian. Shell only for now: settings, status bar, a Sync command.
// The engine (log replay, push, Telegram) comes next; see PROTOCOL.md.
import { App, Notice, Plugin, PluginSettingTab, Setting } from "obsidian";

interface Settings {
  autoSync: boolean;
  pushDelaySeconds: number; // push this long after the last edit
}

const DEFAULTS: Settings = { autoSync: true, pushDelaySeconds: 5 };

export default class TgsyncPlugin extends Plugin {
  settings: Settings = { ...DEFAULTS };
  status!: HTMLElement;

  async onload(): Promise<void> {
    this.settings = { ...DEFAULTS, ...(await this.loadData()) };
    this.status = this.addStatusBarItem();
    this.setStatus("not set up");
    this.addRibbonIcon("refresh-cw", "tgsync: sync now", () => this.syncNow());
    this.addCommand({ id: "sync-now", name: "Sync now", callback: () => this.syncNow() });
    this.addSettingTab(new TgsyncSettingTab(this.app, this));
  }

  setStatus(text: string): void {
    this.status.setText(`tgsync: ${text}`);
  }

  async syncNow(): Promise<void> {
    new Notice("tgsync: sync is not built yet (plugin skeleton).");
  }

  async save(): Promise<void> {
    await this.saveData(this.settings);
  }
}

class TgsyncSettingTab extends PluginSettingTab {
  constructor(app: App, private plugin: TgsyncPlugin) {
    super(app, plugin);
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();
    new Setting(containerEl)
      .setName("Sync automatically")
      .setDesc("Download teammates' changes as they arrive and upload yours after you stop typing.")
      .addToggle((t) => t.setValue(this.plugin.settings.autoSync).onChange(async (v) => {
        this.plugin.settings.autoSync = v;
        await this.plugin.save();
      }));
    new Setting(containerEl)
      .setName("Upload delay (seconds)")
      .setDesc("Wait this long after your last edit before uploading.")
      .addText((t) => t.setValue(String(this.plugin.settings.pushDelaySeconds)).onChange(async (v) => {
        const n = Number(v);
        if (Number.isFinite(n) && n >= 1) {
          this.plugin.settings.pushDelaySeconds = n;
          await this.plugin.save();
        }
      }));
  }
}
