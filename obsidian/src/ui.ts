// SPDX-License-Identifier: AGPL-3.0-or-later
// tgsync's windows and settings tab: log in, start or join a vault, invite, let people in.
import { App, ButtonComponent, Modal, Notice, PluginSettingTab, Setting } from "obsidian";
import type { JoinRequest } from "../../ts/src/protocol.ts";
import type { LoginPrompts } from "../../ts/src/node/telegram.ts";
import type TgsyncPlugin from "./main.ts";

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
  code: () => ask(app, "Log in to Telegram", "Type the login code Telegram just sent you (look in your Telegram app)."),
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

/** "Someone asks to join": the owner types the code that person's tgsync shows them. */
export class AcceptModal extends Modal {
  constructor(app: App, private plugin: TgsyncPlugin, private req: JoinRequest) { super(app); }

  onOpen(): void {
    const who = this.req.name || "Someone";
    this.titleEl.setText(`${who} asks to join this vault`);
    this.contentEl.createEl("p", { text: "Ask them for the code their tgsync shows, and type it here. This makes sure it really is them, " +
      "not someone else who got hold of the invite." });
    let typed = "";
    new Setting(this.contentEl)
      .addText((t) => { t.setPlaceholder("ab12-cd34").onChange((v) => { typed = v; }); window.setTimeout(() => t.inputEl.focus(), 0); })
      .addButton((b) => b.setButtonText("Let in").setCta().onClick(() => busy(b, async () => {
        await this.plugin.setup.accept(this.req, typed);
        new Notice(`tgsync: ${who} is in. Their tgsync finishes joining by itself.`);
        this.close();
      })))
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
          .setDesc(`Tell the person who invited you this code: ${waiting.code}. They type it in their tgsync. ` +
                   "This vault joins by itself as soon as they have; you can close this.")
          .addButton((b) => b.setButtonText("Check now").onClick(() => busy(b, async () => {
            if (await p.finishJoin(true)) again();
          })));
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
            if (w) new Notice(`tgsync: asked to join. Tell the person who invited you this code: ${w.code}`, 0);
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
      .setDesc("Uploads your changes a few seconds after you stop typing, and downloads others' changes every minute and when you come back to Obsidian.")
      .addToggle((t) => t.setValue(p.settings.auto).onChange(async (v) => {
        p.settings.auto = v;
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
      new Setting(list).setName("Members").setDesc(members.map((m) => m.name + (m.admin ? " (admin)" : "") + (m.you ? " (you)" : "")).join(", "));
      for (const r of waiting) {
        new Setting(list).setName(`${r.name || "Someone"} asks to join`)
          .addButton((b) => b.setButtonText("Let in…").setCta().onClick(() => new AcceptModal(this.app, p, r).open()));
      }
      if (!admin) list.createEl("p", { text: "Only admins can let people in." });
    }).catch((e) => { list.empty(); list.createEl("p", { text: `Could not load members: ${(e as Error).message}` }); });
  }
}
