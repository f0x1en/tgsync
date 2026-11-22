// SPDX-License-Identifier: AGPL-3.0-or-later
// tgsync for Obsidian (desktop): a thin layer over the `tgsync` command line program, driven
// through its `--json` mode. It adds nothing the CLI lacks: it checks the group now and then,
// shows what changed, warns when someone else changed a note you are editing, and runs pull/push.
import { App, FileSystemAdapter, Notice, Plugin, PluginSettingTab, Setting, TFile } from "obsidian";

interface Settings {
  cli: string;          // the tgsync program (on PATH, or a full path)
  checkMinutes: number; // look for others' changes this often (0 = never)
}

const DEFAULTS: Settings = { cli: "tgsync", checkMinutes: 2 };

interface Incoming { op: string; path: string; who: string; also_local: boolean }
interface Status {
  ok: boolean; error?: string;
  pending?: { op: string; path: string }[];
  incoming?: Incoming[] | null;
  online_error?: string | null;
}
interface Report { ok: boolean; error?: string; report?: { written: string[]; deleted: string[]; pushed_paths: string[];
  conflicts: [string, string][]; skipped: string[]; problems: string[] } }

export default class TgsyncPlugin extends Plugin {
  settings: Settings = { ...DEFAULTS };
  private bar!: HTMLElement;
  private timer: number | null = null;
  private running = false;
  private lastIncoming = "";

  async onload(): Promise<void> {
    this.settings = { ...DEFAULTS, ...(await this.loadData()) };
    this.bar = this.addStatusBarItem();
    this.bar.addClass("mod-clickable");
    this.bar.onClickEvent(() => this.check(true));
    this.show("…");
    this.addRibbonIcon("refresh-cw", "tgsync: check for changes", () => this.check(true));
    this.addCommand({ id: "check", name: "Check for changes", callback: () => this.check(true) });
    this.addCommand({ id: "pull", name: "Pull (download others' changes)", callback: () => this.pull() });
    this.addCommand({ id: "push", name: "Push (upload your changes)", callback: () => this.push() });
    this.addSettingTab(new TgsyncSettingTab(this.app, this));
    // Warn as soon as you open a note someone else changed.
    this.registerEvent(this.app.workspace.on("file-open", (f) => this.warnIfIncoming(f)));
    this.app.workspace.onLayoutReady(() => { this.check(false); this.schedule(); });
  }

  onunload(): void {
    if (this.timer !== null) window.clearInterval(this.timer);
  }

  schedule(): void {
    if (this.timer !== null) window.clearInterval(this.timer);
    this.timer = null;
    if (this.settings.checkMinutes > 0) {
      this.timer = window.setInterval(() => this.check(false), this.settings.checkMinutes * 60_000);
      this.registerInterval(this.timer);
    }
  }

  private show(text: string): void {
    this.bar.setText(`tgsync: ${text}`);
  }

  private folder(): string {
    const a = this.app.vault.adapter;
    if (!(a instanceof FileSystemAdapter)) throw new Error("tgsync for Obsidian needs the desktop app");
    return a.getBasePath();
  }

  /** Run `tgsync --json <args> -C <vault>`; resolves with its one JSON object. */
  private run<T extends { ok: boolean; error?: string }>(args: string[]): Promise<T> {
    // Desktop only: Obsidian's desktop app gives plugins Node's child_process.
    const { execFile } = require("child_process") as typeof import("child_process");
    return new Promise((resolve) => {
      execFile(this.settings.cli, ["--json", ...args, "-C", this.folder()], { timeout: 10 * 60_000, maxBuffer: 64 << 20 },
        (err, stdout) => {
          try { resolve(JSON.parse(stdout) as T); }
          catch { resolve({ ok: false, error: err ? `could not run ${this.settings.cli}: ${err.message}` : "no answer from tgsync" } as T); }
        });
    });
  }

  private incoming: Incoming[] = [];

  async check(loud: boolean): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      const s = await this.run<Status>(["status"]);
      if (!s.ok) { this.show("error"); if (loud) new Notice(`tgsync: ${s.error}`); return; }
      const mine = s.pending?.length ?? 0;
      if (s.incoming === null || s.incoming === undefined) {
        this.show(`offline${mine ? `, ${mine} to push` : ""}`);
        if (loud) new Notice(`tgsync: could not reach the group (${s.online_error ?? "offline"})`);
        return;
      }
      this.incoming = s.incoming;
      const theirs = s.incoming.length;
      this.show(theirs || mine ? [theirs && `${theirs} to pull`, mine && `${mine} to push`].filter(Boolean).join(", ") : "up to date");
      const key = JSON.stringify(s.incoming.map((x) => [x.op, x.path, x.who]));
      if (theirs && (loud || key !== this.lastIncoming)) {
        const who = [...new Set(s.incoming.map((x) => x.who))].join(", ");
        new Notice(`tgsync: ${theirs} change${theirs > 1 ? "s" : ""} from ${who}. Run "tgsync: Pull" to get ${theirs > 1 ? "them" : "it"}.`, 8000);
        const both = s.incoming.filter((x) => x.also_local);
        if (both.length) new Notice(`tgsync: you and someone else changed ${both.map((x) => x.path).join(", ")}. Push, then pull: notes merge; other files keep both versions.`, 15000);
      } else if (loud && !theirs) new Notice(mine ? `tgsync: nothing new from others; ${mine} change${mine > 1 ? "s" : ""} of yours to push` : "tgsync: up to date");
      this.lastIncoming = key;
      this.warnIfIncoming(this.app.workspace.getActiveFile());
    } finally {
      this.running = false;
    }
  }

  private warnIfIncoming(f: TFile | null): void {
    const x = f && this.incoming.find((i) => i.path === f.path);
    if (x) new Notice(`tgsync: ${x.who} changed this note; pull before you edit it`, 8000);
  }

  private async act(what: "pull" | "push"): Promise<void> {
    if (this.running) { new Notice("tgsync: busy, try again in a moment"); return; }
    this.running = true;
    this.show(what === "pull" ? "pulling…" : "pushing…");
    let r: Report;
    try { r = await this.run<Report>([what]); } finally { this.running = false; }
    if (!r.ok || !r.report) { new Notice(`tgsync: ${r.error}`); await this.check(false); return; }
    const rep = r.report;
    const parts = what === "pull"
      ? [rep.written.length && `${rep.written.length} updated`, rep.deleted.length && `${rep.deleted.length} deleted`]
      : [rep.pushed_paths.length && `${rep.pushed_paths.length} uploaded`];
    new Notice(`tgsync: ${parts.filter(Boolean).join(", ") || "nothing to do"}`);
    for (const [path, copy] of rep.conflicts) new Notice(`tgsync: both changed ${path}; the other version is in ${copy}`, 15000);
    for (const s of [...rep.skipped, ...rep.problems]) new Notice(`tgsync: ${s}`, 15000);
    await this.check(false);
  }

  pull(): Promise<void> { return this.act("pull"); }
  push(): Promise<void> { return this.act("push"); }

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
    containerEl.createEl("p", { text: "This vault folder must be a tgsync vault (set it up with `tgsync new` or `tgsync join` in a terminal)." });
    new Setting(containerEl)
      .setName("tgsync program")
      .setDesc("The tgsync command line program: just `tgsync` if it is on your PATH, else its full path.")
      .addText((t) => t.setValue(this.plugin.settings.cli).onChange(async (v) => {
        this.plugin.settings.cli = v.trim() || "tgsync";
        await this.plugin.save();
      }));
    new Setting(containerEl)
      .setName("Check for changes every (minutes)")
      .setDesc("Looks at the group for teammates' changes and tells you. Downloads nothing. 0 = only when you ask.")
      .addText((t) => t.setValue(String(this.plugin.settings.checkMinutes)).onChange(async (v) => {
        const n = Number(v);
        if (Number.isFinite(n) && n >= 0) {
          this.plugin.settings.checkMinutes = n;
          await this.plugin.save();
          this.plugin.schedule();
        }
      }));
  }
}
