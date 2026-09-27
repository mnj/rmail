import { useMemo, useState } from 'react';
import { RefreshCw, RotateCcw, Save, Search, ServerCog, Trash2 } from 'lucide-react';
import { api, Setting, SettingsView } from '../api';
import { Empty, ErrorBanner, Toggle, useFeedback, useResource } from '../ui';

/** Draft edits keyed by setting key. `null` means "reset to default". */
type Drafts = Record<string, unknown>;

const isEqual = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

function listToText(value: unknown): string {
  return Array.isArray(value) ? value.join('\n') : '';
}

function textToList(text: string): string[] {
  return text.split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
}

function describe(value: unknown): string {
  if (value === null || value === undefined) return 'none';
  if (Array.isArray(value)) return value.length ? value.join(', ') : 'empty';
  if (typeof value === 'boolean') return value ? 'on' : 'off';
  return String(value);
}

export function SettingControl({ setting, value, onChange, labels }: { setting: Setting; value: unknown; onChange: (value: unknown) => void; labels?: Record<string, string> }) {
  const kind = setting.kind;
  const effective = value ?? setting.default;
  switch (kind.type) {
    case 'bool':
      return <Toggle label={setting.label} checked={Boolean(effective)} onChange={onChange} />;
    case 'integer':
      return (
        <input
          type="number"
          min={kind.min}
          max={kind.max}
          value={effective === null || effective === undefined ? '' : String(effective)}
          placeholder={describe(setting.default)}
          onChange={(event) => onChange(event.target.value === '' ? null : Number(event.target.value))}
        />
      );
    case 'choice':
      return (
        <select value={String(effective ?? '')} onChange={(event) => onChange(event.target.value)}>
          {effective === undefined || effective === null ? <option value="">Select…</option> : null}
          {kind.options.map((option) => <option key={option} value={option}>{labels?.[option] ?? option}</option>)}
        </select>
      );
    case 'multi_choice': {
      const selected = Array.isArray(effective) ? (effective as string[]) : [];
      return (
        <div className="chips">
          {kind.options.map((option) => {
            const active = selected.includes(option);
            return (
              <button
                type="button"
                key={option}
                className={`chip ${active ? 'active' : ''}`}
                aria-pressed={active}
                onClick={() => onChange(active ? selected.filter((item) => item !== option) : kind.options.filter((item) => item === option || selected.includes(item)))}
              >
                {option}
              </button>
            );
          })}
        </div>
      );
    }
    case 'list':
    case 'address_list':
      return (
        <textarea
          rows={Math.max(2, Math.min(6, (Array.isArray(effective) ? effective.length : 0) + 1))}
          value={listToText(effective)}
          placeholder={kind.type === 'address_list' ? 'One address per line, e.g. [::]:25 or 127.0.0.1:8080' : 'One value per line'}
          onChange={(event) => onChange(textToList(event.target.value))}
          spellCheck={false}
        />
      );
    case 'secret':
      return (
        <input
          type="password"
          autoComplete="new-password"
          value={typeof value === 'string' ? value : ''}
          placeholder={setting.is_set ? '•••••••• (set — type to replace)' : 'Not set'}
          onChange={(event) => onChange(event.target.value)}
        />
      );
    default:
      return (
        <input
          type="text"
          value={typeof effective === 'string' ? effective : ''}
          placeholder={setting.default ? describe(setting.default) : 'Not set'}
          onChange={(event) => onChange(event.target.value)}
          spellCheck={false}
        />
      );
  }
}

export function SettingsPage() {
  const { run, confirm, notify } = useFeedback();
  const resource = useResource(() => api<SettingsView>('/api/settings'), []);
  const [drafts, setDrafts] = useState<Drafts>({});
  const [filter, setFilter] = useState('');
  const [group, setGroup] = useState<string>('all');
  const [saving, setSaving] = useState(false);
  const view = resource.data;

  // Certificate settings have their own page.
  const settings = view && view.managed ? view.settings.filter((setting) => setting.group !== 'acme') : [];
  const dirtyKeys = Object.keys(drafts);

  const visible = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return settings.filter((setting) =>
      (group === 'all' || setting.group === group) &&
      (!needle || `${setting.label} ${setting.key} ${setting.help}`.toLowerCase().includes(needle)));
  }, [settings, filter, group]);

  if (resource.error) return <ErrorBanner error={resource.error} />;
  if (!view) return <Empty>Loading settings…</Empty>;
  if (!view.managed) {
    return (
      <article className="panel callout">
        <ServerCog size={28} />
        <div>
          <h2>Settings are read from the configuration file</h2>
          <p>Set <code>db_path</code> in the configuration file to manage settings here. On the next start every value in the file is imported into the database once, and the file then only needs <code>mail_root</code> and <code>db_path</code>.</p>
        </div>
      </article>
    );
  }

  const valueOf = (setting: Setting) => (setting.key in drafts ? drafts[setting.key] : setting.value);

  const change = (setting: Setting, value: unknown) => {
    setDrafts((current) => {
      const next = { ...current };
      const original = setting.kind.type === 'secret' ? undefined : setting.value;
      if (isEqual(value, original) || (setting.kind.type === 'secret' && value === '')) delete next[setting.key];
      else next[setting.key] = value;
      return next;
    });
  };

  async function save() {
    setSaving(true);
    const changes = Object.fromEntries(dirtyKeys.map((key) => [key, drafts[key]]));
    const ok = await run(async () => {
      const updated = await api<SettingsView>('/api/settings', 'PUT', { changes });
      resource.setData(updated);
      setDrafts({});
    }, `Saved ${dirtyKeys.length} setting${dirtyKeys.length === 1 ? '' : 's'}`);
    setSaving(false);
    if (ok) notify('info', 'Restart the affected services to apply the changes.');
  }

  async function reset(setting: Setting) {
    const ok = await confirm({
      title: `Reset ${setting.label}?`,
      message: <>The stored value is removed and the built-in default ({describe(setting.default)}) applies.</>,
      confirmLabel: 'Reset',
    });
    if (ok) setDrafts((current) => ({ ...current, [setting.key]: null }));
  }

  async function removeOther(key: string) {
    const ok = await confirm({ title: `Remove ${key}?`, message: 'This legacy value will no longer be passed to the services.', confirmLabel: 'Remove', danger: true });
    if (!ok) return;
    await run(async () => {
      resource.setData(await api<SettingsView>('/api/settings', 'PUT', { changes: { [key]: null } }));
    }, `Removed ${key}`);
  }

  const restartNeeded = view.services.filter((service) => service.restart_required);
  const groupsWithSettings = view.groups.filter((item) => settings.some((setting) => setting.group === item.id));

  return (
    <div className="settingsPage">
      {restartNeeded.length > 0 && (
        <div className="notice warn">
          <RefreshCw size={18} />
          <div>
            <strong>Restart needed to apply saved changes</strong>
            {restartNeeded.map((service) => (
              <p key={service.service}><code>{service.service}</code> — {service.pending_changes.join(', ')}</p>
            ))}
            <p>Run <code>rmail_ctl service restart {restartNeeded.map((service) => `--unit ${service.service}`).join(' ')}</code> or restart the systemd units.</p>
          </div>
        </div>
      )}

      <div className="settingsLayout">
        <nav className="settingsNav" aria-label="Setting groups">
          <button className={group === 'all' ? 'active' : ''} onClick={() => setGroup('all')}>All settings <small>{settings.length}</small></button>
          {groupsWithSettings.map((item) => {
            const dirty = settings.filter((setting) => setting.group === item.id && setting.key in drafts).length;
            return (
              <button key={item.id} className={group === item.id ? 'active' : ''} onClick={() => setGroup(item.id)}>
                {item.label}{dirty > 0 && <i className="dirtyDot" aria-label={`${dirty} unsaved`} />}
              </button>
            );
          })}
          {view.other.length > 0 && <button className={group === 'other' ? 'active' : ''} onClick={() => setGroup('other')}>Other stored keys <small>{view.other.length}</small></button>}
        </nav>

        <div className="settingsMain">
          <div className="settingsToolbar">
            <div className="searchBox"><Search size={16} /><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Search settings" /></div>
            <span className="muted">Revision {view.revision}{view.imported_from ? ` · imported from ${view.imported_from}` : ''}</span>
          </div>

          {group === 'other' ? (
            <article className="panel">
              <div className="panelHead"><div><h2>Other stored keys</h2><small>Values imported from the configuration file that have no dedicated control, such as legacy listener fields.</small></div></div>
              <table>
                <thead><tr><th>Key</th><th>Value</th><th /></tr></thead>
                <tbody>
                  {view.other.map((item) => (
                    <tr key={item.key}><td><code>{item.key}</code></td><td><code>{JSON.stringify(item.value)}</code></td><td className="rowActions"><button className="iconButton danger" title="Remove" onClick={() => removeOther(item.key)}><Trash2 size={15} /></button></td></tr>
                  ))}
                </tbody>
              </table>
            </article>
          ) : (
            (group === 'all' ? groupsWithSettings : groupsWithSettings.filter((item) => item.id === group)).map((item) => {
              const rows = visible.filter((setting) => setting.group === item.id);
              if (!rows.length) return null;
              return (
                <article className="panel settingsGroup" key={item.id}>
                  <div className="panelHead"><div><h2>{item.label}</h2><small>{item.description}</small></div></div>
                  <div className="settingRows">
                    {rows.map((setting) => {
                      const draft = setting.key in drafts;
                      const current = valueOf(setting);
                      const custom = draft ? drafts[setting.key] !== null : setting.is_set;
                      return (
                        <div className={`settingRow ${draft ? 'dirty' : ''}`} key={setting.key}>
                          <div className="settingInfo">
                            <strong>{setting.label}{custom && <span className="badge">custom</span>}{draft && <span className="badge dirty">unsaved</span>}</strong>
                            {setting.help && <p>{setting.help}</p>}
                            <small><code>{setting.key}</code> · {setting.services.length ? `applies to ${setting.services.join(', ')} on restart` : 'applies immediately'}{setting.kind.type !== 'secret' && setting.default !== null && setting.default !== undefined ? ` · default ${describe(setting.default)}` : ''}</small>
                          </div>
                          <div className="settingControl">
                            <SettingControl setting={setting} value={current === null ? undefined : current} onChange={(value) => change(setting, value)} />
                            {custom && !draft && <button className="linkButton" onClick={() => reset(setting)}><RotateCcw size={13} /> {setting.kind.type === 'secret' ? 'Clear' : 'Reset to default'}</button>}
                            {draft && <button className="linkButton" onClick={() => setDrafts((all) => { const next = { ...all }; delete next[setting.key]; return next; })}>Undo</button>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </article>
              );
            })
          )}
          {group !== 'other' && visible.length === 0 && <Empty>No settings match “{filter}”.</Empty>}
        </div>
      </div>

      {dirtyKeys.length > 0 && (
        <div className="saveBar">
          <span><strong>{dirtyKeys.length}</strong> unsaved change{dirtyKeys.length === 1 ? '' : 's'}</span>
          <button className="button" onClick={() => setDrafts({})} disabled={saving}>Discard</button>
          <button className="button primary" onClick={save} disabled={saving}><Save size={16} />{saving ? 'Saving…' : 'Save changes'}</button>
        </div>
      )}
    </div>
  );
}
