// SPDX-License-Identifier: AGPL-3.0-or-later
// tgsync for Obsidian (desktop): keeps this vault in sync through its private Telegram group, like
// Obsidian Sync. The sync engine runs inside the plugin (no separate program). It uploads your
// changes a few seconds after you stop typing, and downloads others' changes every few seconds (as set; slower when Telegram asks), when
// Obsidian opens and when you come back to it. Notes that two people edit merge; other files keep both.
import { FileSystemAdapter, MarkdownView, Notice, Plugin } from "obsidian";
import { VaultHost } from "../../ts/src/node/host.ts";
import { LockBusy } from "../../ts/src/node/lock.ts";
import { Pace } from "../../ts/src/node/pace.ts";
import { OfflineError } from "../../ts/src/transport.ts";
import type { Report } from "../../ts/src/vault.ts";
import { VaultSetup, withCode, type Advanced, type Ask } from "./setup.ts";
import { AcceptModal, TgsyncSettingTab, VersionsModal } from "./ui.ts";

interface Settings extends Advanced {
  auto: boolean; // sync automatically
  every: number; // seconds between looks for others' changes, as set; Telegram's Pace may stretch it
  refused: string[]; // join requests refused (their keys): not asked again
}

const DEFAULTS: Settings = { auto: true, every: 10, apiId: "", apiHash: "", proxy: "", account: "", refused: [] };

/** What the status bar shows. */
type State = "synced" | "syncing" | "offline" | "paused" | "not set up" | "waiting" | "error";

export default class TgsyncPlugin extends Plugin {
  settings: Settings = { ...DEFAULTS };
  host: VaultHost | null = null;
  setup!: VaultSetup;
  state: State = "synced";
  lastError = "";
  /** ms to wait after the last edit before uploading. */
  editDelay = 5_000;
  /** This account's Pace: how much Telegram wants us to slow down now (1 = not at all). */
  pace(): Pace { return Pace.of(this.setup.profile()); }
  /** ms between looks for others' changes (idle, one look is one Telegram call): as set, times the Pace. */
  pollEvery(): number { return this.settings.every * 1000 * this.pace().now(); }
  /** ms between looks while waiting to be let in (each reads the whole group: fewer). */
  joinEvery(): number { return 3 * this.pollEvery(); }
  private lastJoinTry = 0;
  /** ms between full looks for people asking to join (each reads all the group's join messages);
   *  a new join message seen while syncing triggers a look at once. */
  askEvery(): number { return 10 * 60_000 * this.pace().now(); }
  private lastAsk = 0;
  /** Admins: people asking to join, until let in or refused (shown in the status bar). */
  pending: Ask[] = [];
  private bar!: HTMLElement;
  private running: Promise<void> | null = null;
  private again = false;
  private editTimer: number | null = null;
  private pollTimer: number | null = null;

  async onload(): Promise<void> {
    this.settings = { ...DEFAULTS, ...(await this.loadData()) };
    this.bar = this.addStatusBarItem();
    this.bar.addClass("mod-clickable");
    this.bar.onClickEvent(() => this.clickBar());
    this.addRibbonIcon("refresh-cw", "Sync now (tgsync)", () => this.sync(true));
    this.addCommand({ id: "sync", name: "Sync now", callback: () => this.sync(true) });
    this.addCommand({
      id: "versions", name: "Older versions of this file",
      checkCallback: (checking) => {
        const f = this.app.workspace.getActiveFile();
        if (!f || !this.host?.cfg()) return false;
        if (!checking) new VersionsModal(this.app, this, f.path).open();
        return true;
      },
    });
    this.addSettingTab(new TgsyncSettingTab(this.app, this));
    this.host = new VaultHost(this.folder());
    this.setup = new VaultSetup(this.folder(), this.host, () => this.settings.account);
    for (const ev of ["modify", "create", "delete", "rename"] as const) {
      this.registerEvent(this.app.vault.on(ev as "modify", () => this.edited()));
    }
    this.registerDomEvent(window, "focus", () => this.autoSync());
    this.app.workspace.onLayoutReady(() => { this.schedule(); this.autoSync(); void this.firstRun(); });
  }

  /** Not set up yet: say how, once per start. */
  private async firstRun(): Promise<void> {
    if (this.host?.cfg() || await this.setup.waiting()) return;
    const n: any = new Notice("tgsync: click here to set up syncing for this vault.", 15_000);
    n.noticeEl?.addEventListener("click", () => this.openSettings());
  }

  openSettings(): void {
    const s = (this.app as any).setting;
    s?.open();
    s?.openTabById(this.manifest?.id ?? "tgsync");
  }

  async onunload(): Promise<void> {
    this.stopTimers();
    await this.host?.close();
  }

  private folder(): string {
    const a = this.app.vault.adapter;
    if (!(a instanceof FileSystemAdapter)) throw new Error("tgsync needs the desktop app for now");
    return a.getBasePath();
  }

  private stopTimers(): void {
    if (this.pollTimer !== null) window.clearTimeout(this.pollTimer);
    if (this.editTimer !== null) window.clearTimeout(this.editTimer);
    this.pollTimer = this.editTimer = null;
  }

  /** (Re)start the timers after a settings change. */
  schedule(): void {
    this.stopTimers();
    if (!this.settings.auto) { this.show("paused"); return; }
    const next = () => { // a timeout each time: the gap follows the Pace
      this.pollTimer = window.setTimeout(() => { this.autoSync(); next(); }, this.pollEvery());
    };
    next();
    if (this.state === "paused") this.show("synced");
  }

  private edited(): void {
    if (!this.settings.auto) return;
    if (this.editTimer !== null) window.clearTimeout(this.editTimer);
    this.editTimer = window.setTimeout(() => { this.editTimer = null; this.autoSync(); }, this.editDelay);
  }

  private autoSync(): void {
    if (this.settings.auto) void this.sync(false);
  }

  private clickBar(): void {
    if (this.pending.length) { this.askAccept(this.pending[0]); return; }
    if (this.state === "not set up" || this.state === "waiting") { this.openSettings(); return; }
    if (this.state === "error" || this.state === "offline") new Notice(`tgsync: ${this.lastError}`, 10_000);
    void this.sync(true);
  }

  show(state: State): void {
    this.state = state;
    const text: Record<State, string> = {
      synced: "✓ Synced", syncing: "↻ Syncing…", offline: "Offline", paused: "Sync paused",
      "not set up": "tgsync: not set up", waiting: "tgsync: waiting to be let in", error: "⚠ Sync problem",
    };
    const n = this.pending.length;
    this.bar.setText(text[state] + (n ? ` · ${n} waiting to join` : ""));
    this.bar.setAttr?.("aria-label", state === "error" || state === "offline" ? this.lastError : "tgsync: click to sync now");
  }

  /** Upload yours, then download others'. One at a time; a request during a run runs once more after it. */
  sync(loud: boolean): Promise<void> {
    if (this.running) { this.again = true; return this.running; }
    this.running = (async () => {
      do {
        this.again = false;
        await this.syncOnce(loud);
      } while (this.again);
    })().finally(() => { this.running = null; });
    return this.running;
  }

  private async syncOnce(loud: boolean): Promise<void> {
    if (!this.host?.cfg() && !(await this.finishJoin(loud))) return;
    this.show("syncing");
    try {
      await this.saveEditors();
      const [pushed, pulled, asks] = await this.host!.use(async (v) => [await v.pushChanges(), await v.pullChanges(), v.asks] as const);
      this.tell(pushed, pulled, loud);
      this.show(this.settings.auto ? "synced" : "paused");
      await this.lookForRequests(asks > 0);
    } catch (e) {
      if (e instanceof LockBusy) { this.show(this.settings.auto ? "synced" : "paused"); this.again = false; return; } // a terminal run is busy: next time
      this.lastError = (e as Error).message || String(e);
      this.show(e instanceof OfflineError || /reach Telegram/i.test(this.lastError) ? "offline" : "error");
      if (loud) new Notice(`tgsync: ${this.lastError}`, 10_000);
    }
  }

  /** Not set up: if this vault asked to join, see whether we were let in (then download). -> set up now? */
  async finishJoin(loud: boolean): Promise<boolean> {
    if (this.host?.cfg()) return true;
    const w = await this.setup.waiting();
    if (!w) {
      this.show("not set up");
      if (loud) new Notice("tgsync: this vault is not set up for syncing yet (see the tgsync settings)");
      return false;
    }
    if (!loud && Date.now() - this.lastJoinTry < this.joinEvery()) return false;
    this.lastJoinTry = Date.now();
    this.show("syncing");
    try {
      if (await this.setup.join()) {
        this.show("waiting");
        if (loud) new Notice("tgsync: not let in yet. The vault's owner is asked to let you in.");
        return false;
      }
    } catch (e) {
      if (e instanceof LockBusy) { this.show("waiting"); return false; }
      this.lastError = (e as Error).message || String(e);
      this.show(e instanceof OfflineError || /reach Telegram/i.test(this.lastError) ? "offline" : "error");
      if (loud) new Notice(`tgsync: ${this.lastError}`, 10_000);
      return false;
    }
    new Notice("tgsync: you were let in. This vault is now in sync.");
    return true;
  }

  /** Admins: someone asks to join? Ask at once whether to let them in; the request then waits in the
   *  status bar until let in or refused (never asked again if refused). `news`: a join message just came. */
  private async lookForRequests(news: boolean): Promise<void> {
    if (!news && Date.now() - this.lastAsk < this.askEvery()) return;
    this.lastAsk = Date.now();
    let reqs: Ask[];
    try {
      reqs = await this.host!.use(async (v) => (v.isAdmin ? (await v.pendingRequests()).map(withCode) : []));
    } catch { return; } // next time
    const known = new Set(this.pending.map((r) => r.recipient));
    this.pending = reqs.filter((r) => !this.settings.refused.includes(r.recipient));
    this.show(this.state);
    for (const r of this.pending) if (!known.has(r.recipient)) this.askAccept(r);
  }

  askAccept(r: Ask): void {
    new AcceptModal(this.app, this, r).open();
  }

  /** Let in or refused: no longer waiting. */
  decided(r: Ask): void {
    this.pending = this.pending.filter((p) => p.recipient !== r.recipient);
    this.show(this.state);
  }

  async refuse(r: Ask): Promise<void> {
    this.settings.refused.push(r.recipient);
    await this.save();
    this.decided(r);
  }

  /** Only what needs the user's attention; quiet otherwise (like Obsidian Sync). */
  private tell(pushed: Report, pulled: Report, loud: boolean): void {
    for (const [path, copy] of [...pushed.conflicts, ...pulled.conflicts]) {
      new Notice(`tgsync: ${path} was changed on two devices at once. Both versions are kept: the other one is "${copy}".`, 15_000);
    }
    for (const s of [...pushed.skipped, ...pulled.skipped, ...pushed.problems, ...pulled.problems]) new Notice(`tgsync: ${s}`, 15_000);
    if (loud) {
      const n = pushed.pushed_paths.length, m = pulled.written.length + pulled.deleted.length;
      new Notice(`tgsync: ${n || m ? [n && `${n} uploaded`, m && `${m} downloaded`].filter(Boolean).join(", ") : "everything is up to date"}`);
    }
  }

  /** Write what is typed in open notes to disk first (Obsidian saves with a short delay). */
  private async saveEditors(): Promise<void> {
    for (const leaf of this.app.workspace.getLeavesOfType("markdown")) {
      if (leaf.view instanceof MarkdownView) await leaf.view.save();
    }
  }

  async save(): Promise<void> {
    await this.saveData(this.settings);
  }
}
