// SPDX-License-Identifier: AGPL-3.0-or-later
// tgsync's windows and settings tab: log in, start or join a vault, invite, let people in.
import { App, ButtonComponent, Modal, Notice, PluginSettingTab, Setting } from "obsidian";
import type { LoginPrompts } from "../../ts/src/node/telegram.ts";
import type TgsyncPlugin from "./main.ts";
import { named, type Ask } from "./setup.ts";

/** Ask one thing in a window. Closing it without an answer cancels. */
export function ask(app: App, title: string, desc: string, secret = false): Promise<string> {
  return new Promise((ok, no) => {
    let answered = false, value = "";
    const m = new Modal(app);
    m.titleEl.setText(title);
    m.contentEl.createEl("p", { text: desc });
    const done = () => { if (!value.trim()) return; answered = true; m.close(); ok(value.trim()); };
    new Setting(m.contentEl)
      .addText((t) => {
        if (secret) t.inputEl.type = "password";
        t.onChange((v) => { value = v; });
        t.inputEl.addEventListener("keydown", (e) => { if (e.key === "Enter") done(); });
        window.setTimeout(() => t.inputEl.focus(), 0);
      })
      .addButton((b) => b.setButtonText("Continue").setCta().onClick(done));
    m.onClose = () => { if (!answered) no(new Error("Cancelled.")); };
    m.open();
  });
}

export const loginPrompts = (app: App): LoginPrompts => ({
  phone: () => ask(app, "Log in to Telegram", "Your phone number, with the country code (for example +491701234567)."),
  code: (where) => ask(app, "Log in to Telegram", `Type the login code. ${where}.`),
  password: () => ask(app, "Log in to Telegram", "Your account has two-step verification. Type its password.", true),
});

/** Run a button's action: the button waits while it runs; a problem is shown, not thrown. */
async function busy(b: ButtonComponent, fn: () => Promise<void>): Promise<void> {
  b.setDisabled(true);
  try { await fn(); } catch (e) {
    const msg = (e as Error).message || String(e);
    if (msg !== "Cancelled.") new Notice(`tgsync: ${msg}`, 15_000);
  } finally { b.setDisabled(false); }
}

/** Ask yes or no in a window. -> true for `yes`. */
export function confirm(app: App, title: string, desc: string, yes: string): Promise<boolean> {
  return new Promise((ok) => {
    let said = false;
    const m = new Modal(app);
    m.titleEl.setText(title);
    m.contentEl.createEl("p", { text: desc });
    new Setting(m.contentEl)
      .addButton((b) => b.setButtonText(yes).setWarning().onClick(() => { said = true; m.close(); }))
      .addButton((b) => b.setButtonText("Cancel").onClick(() => m.close()));
    m.onClose = () => ok(said);
    m.open();
  });
}

/** Older versions of one file, from the vault's history: pick one to bring back. */
export class VersionsModal extends Modal {
  constructor(app: App, private plugin: TgsyncPlugin, private path: string) { super(app); }

  onOpen(): void {
    this.titleEl.setText(`Versions of ${this.path}`);
    const el = this.contentEl;
    el.createEl("p", { text: "Loading…" });
    this.plugin.setup.versions(this.path).then((rows) => {
      el.empty();
      if (!rows.length) { el.createEl("p", { text: "No versions yet: the file's history starts at its first upload." }); return; }
      el.createEl("p", { text: "Restoring puts that version in place of the current one. The current one stays in the history." });
      for (const r of rows) {
        new Setting(el).setName(new Date(r.ts * 1000).toLocaleString()).setDesc(r.who)
          .addButton((b) => b.setButtonText("Restore").onClick(() => busy(b, async () => {
            await this.plugin.setup.restore(this.path, r.rev);
            new Notice(`tgsync: ${this.path} is back as of ${new Date(r.ts * 1000).toLocaleString()}.`);
            this.close();
            void this.plugin.sync(false);
          })));
      }
    }).catch((e) => { el.empty(); el.createEl("p", { text: `Could not load the history: ${(e as Error).message}` }); });
  }
}

/** "Someone asks to join": let in, or refuse (not asked again). Not now: it waits in the status bar. */
export class AcceptModal extends Modal {
  constructor(app: App, private plugin: TgsyncPlugin, private req: Ask) { super(app); }

  onOpen(): void {
    const who = named(this.req.name, this.req.code);
    this.titleEl.setText(`${who} asks to join this vault`);
    this.contentEl.createEl("p", { text: "They used an invite to this vault. Let them in only if you know who this is: " +
      `members can read and change everything in the vault. Their tgsync shows them the code ${this.req.code}; ` +
      "if two people have the same name, ask which code they see." });
    new Setting(this.contentEl)
      .addButton((b) => b.setButtonText("Let in").setCta().onClick(() => busy(b, async () => {
        await this.plugin.setup.accept(this.req);
        this.plugin.decided(this.req);
        new Notice(`tgsync: ${who} is in. Their tgsync finishes joining by itself.`);
        this.close();
      })))
      .addButton((b) => b.setButtonText("Refuse").onClick(async () => { await this.plugin.refuse(this.req); this.close(); }))
      .addButton((b) => b.setButtonText("Not now").onClick(() => this.close()));
  }
}

export class TgsyncSettingTab extends PluginSettingTab {
  constructor(app: App, private plugin: TgsyncPlugin) { super(app, plugin); }

  display(): void {
    void this.render();
  }

  private async render(): Promise<void> {
    const { containerEl: el } = this;
    const p = this.plugin, s = p.setup;
    el.empty();
    const again = () => this.display();

    // ---------------------------------------------------------------- Telegram account
    el.createEl("h3", { text: "Telegram account" });
    if (s.loggedIn()) {
      new Setting(el).setName("Logged in").setDesc(`Account '${s.profile()}'. Your vault is kept, encrypted, in a private Telegram group only its members can read.`);
    } else {
      new Setting(el).setName("Log in to Telegram")
        .setDesc("tgsync keeps this vault, encrypted, in a private Telegram group of your own: free storage, only members can read it. " +
                 "Log in with your phone number; Telegram sends you a code.")
        .addButton((b) => b.setButtonText("Log in").setCta().onClick(() => busy(b, async () => {
          const who = await s.login(p.settings, loginPrompts(this.app));
          new Notice(`tgsync: logged in as ${who}`);
          again();
        })));
    }

    // ---------------------------------------------------------------- this vault
    if (s.loggedIn()) {
      el.createEl("h3", { text: "This vault" });
      const waiting = await s.waiting();
      if (p.host?.cfg()) this.vaultSettings(el);
      else if (waiting) {
        new Setting(el).setName("Waiting to be let in")
          .setDesc(`The vault's owner is asked to let you in; they see your name with the code ${waiting.code}. ` +
                   "This vault joins by itself as soon as they have; you can close this.");
      } else {
        new Setting(el).setName("Start syncing this vault")
          .setDesc("Makes a private Telegram group for this vault and uploads its files there, encrypted. Then invite your other devices or friends.")
          .addButton((b) => b.setButtonText("Start").setCta().onClick(() => busy(b, async () => {
            await s.create();
            new Notice("tgsync: this vault now syncs. Invite others from the tgsync settings.");
            await p.sync(true);
            again();
          })));
        let line = "";
        new Setting(el).setName("Join a vault")
          .setDesc("Paste the invite you were sent. Notes already in this vault are added to the shared one.")
          .addText((t) => t.setPlaceholder("tgsync1-…").onChange((v) => { line = v; }))
          .addButton((b) => b.setButtonText("Join").setCta().onClick(() => busy(b, async () => {
            const w = await s.join(line);
            if (w) new Notice(`tgsync: asked to join (your code: ${w.code}). You are in as soon as the vault's owner lets you in.`);
            else { new Notice("tgsync: joined. Your vault is in sync."); p.schedule(); }
            again();
          })));
      }
    }

    // ---------------------------------------------------------------- advanced
    el.createEl("h3", { text: "Advanced" });
    const field = (name: string, desc: string, key: "apiId" | "apiHash" | "proxy", hint: string) =>
      new Setting(el).setName(name).setDesc(desc).addText((t) => t.setPlaceholder(hint).setValue(p.settings[key]).onChange(async (v) => {
        p.settings[key] = v.trim();
        await p.save();
      }));
    if (!p.host?.cfg()) {
      new Setting(el).setName("Account")
        .setDesc("Which tgsync account this vault uses on this computer. Leave empty for the usual one; " +
                 "give another name (for example b) to use a second Telegram account. Set it before you log in and start or join.")
        .addText((t) => {
          t.setPlaceholder(s.profile()).setValue(p.settings.account).onChange(async (v) => { p.settings.account = v.trim(); await p.save(); });
          t.inputEl.addEventListener("change", again); // shows that account's login state
        });
    }
    field("Own Telegram API id", "Optional: use your own API key from my.telegram.org → API development tools. Used at the next log in.", "apiId", "1234567");
    field("Own Telegram API hash", "Goes with the API id.", "apiHash", "0123456789abcdef…");
    field("Proxy", "If Telegram is blocked where you are. Used at the next log in.", "proxy", "socks5://127.0.0.1:1080");
  }

  private vaultSettings(el: HTMLElement): void {
    const p = this.plugin;
    new Setting(el)
      .setName("Sync automatically")
      .setDesc("Uploads your changes a few seconds after you stop typing, and downloads others' changes regularly (see below) and when you come back to Obsidian.")
      .addToggle((t) => t.setValue(p.settings.auto).onChange(async (v) => {
        p.settings.auto = v;
        await p.save();
        p.schedule();
      }));
    const f = p.pace().now();
    new Setting(el)
      .setName("Look for changes every")
      .setDesc(`${p.settings.every} seconds. ` + (f > 1
        ? `Telegram asked tgsync to slow down, so for now it is every ${Math.round(p.settings.every * f)} seconds; ` +
          "it goes back by itself once Telegram is calm."
        : "If Telegram asks tgsync to slow down, it waits longer by itself, then goes back to this."))
      .addSlider((sl) => sl.setLimits(5, 120, 5).setValue(p.settings.every).setDynamicTooltip().onChange(async (v) => {
        p.settings.every = v;
        await p.save();
        p.schedule();
      }));
    new Setting(el).setName("Invite someone")
      .setDesc("Copies an invite. Send it to them (or to yourself, for another device); they paste it in tgsync's settings under “Join a vault”.")
      .addButton((b) => b.setButtonText("Copy invite").onClick(() => busy(b, async () => {
        await navigator.clipboard.writeText(await p.setup.invite());
        new Notice("tgsync: invite copied. When they paste it, you are asked to let them in.");
      })));
    const list = el.createDiv();
    list.createEl("p", { text: "Loading members…" });
    p.setup.members().then(({ admin, members, waiting }) => {
      list.empty();
      list.createEl("h4", { text: "Members" });
      for (const m of members) {
        const row = new Setting(list).setName(m.name + (m.you ? " (you)" : "")).setDesc(m.admin ? "Admin: can let people in and remove them." : "");
        if (admin && !m.you && !m.admin) {
          row.addButton((b) => b.setButtonText("Make admin").onClick(() => busy(b, async () => {
            await p.setup.giveAdmin(m.id);
            new Notice(`tgsync: ${m.name} is now an admin.`);
            this.display();
          })));
        }
        if (admin && !m.you) {
          row.addButton((b) => b.setButtonText("Remove…").setWarning().onClick(() => busy(b, async () => {
            if (!await confirm(this.app, `Remove ${m.name}?`, "They keep what they already have, but cannot read anything new: " +
              "the vault gets a new key.", "Remove")) return;
            await p.setup.remove(m.id);
            new Notice(`tgsync: ${m.name} was removed.`);
            this.display();
          })));
        }
        if (m.you && m.admin) {
          row.addButton((b) => b.setButtonText("Stop being admin").onClick(() => busy(b, async () => {
            if (!await confirm(this.app, "Stop being an admin?", "You can no longer let people in or remove them. Another admin can make you one again.", "Stop")) return;
            await p.setup.dropAdmin();
            this.display();
          })));
        }
      }
      for (const r of waiting.filter((r) => !p.settings.refused.includes(r.recipient))) {
        new Setting(list).setName(`${named(r.name, r.code)} asks to join`)
          .addButton((b) => b.setButtonText("Let in…").setCta().onClick(() => new AcceptModal(this.app, p, r).open()));
      }
      if (!admin) list.createEl("p", { text: "Only admins can let people in." });
    }).catch((e) => { list.empty(); list.createEl("p", { text: `Could not load members: ${(e as Error).message}` }); });
  }
}
