// Contacts: the user's CardDAV address books, so what is added here shows
// up on their phone and the other way round. Only the fields shown here are
// changed when a contact is edited; everything else on the card is kept.

import { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, BookUser, Cake, Mail, MapPin, Pencil, Phone, Plus, Search, Trash2, X } from 'lucide-react';
import { Api } from './types';

type Entry = { kind: string; value: string };
type PostalAddress = { kind: string; street: string; city: string; region: string; postcode: string; country: string };
export type ContactFields = {
  full_name: string; given: string; family: string;
  emails: Entry[]; phones: Entry[];
  org: string; title: string; birthday: string; note: string;
  addresses: PostalAddress[];
};
type Contact = ContactFields & { book: string; name: string; etag: string; has_photo: boolean };
type Book = { id: string; displayname: string; owner?: string; writable: boolean };
type Listing = { books: Book[]; contacts: Contact[] };

/** A new contact, optionally from a message's sender. */
export type ContactSeed = { name?: string; email?: string };

const emptyFields = (): ContactFields => ({
  full_name: '', given: '', family: '', emails: [], phones: [], org: '', title: '', birthday: '', note: '', addresses: [],
});

function displayName(contact: ContactFields): string {
  return contact.full_name || [contact.given, contact.family].filter(Boolean).join(' ') || contact.org || contact.emails[0]?.value || '(no name)';
}

function initials(contact: ContactFields): string {
  const name = displayName(contact).replace(/[^\p{L}\p{N} ]/gu, ' ').trim();
  const parts = name.split(/\s+/).filter(Boolean);
  return ((parts[0]?.[0] ?? '?') + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase();
}

function matches(contact: Contact, query: string): boolean {
  if (!query) return true;
  const needle = query.toLowerCase();
  return [displayName(contact), contact.org, contact.title, ...contact.emails.map((e) => e.value), ...contact.phones.map((p) => p.value)]
    .some((value) => value.toLowerCase().includes(needle));
}

/** "12 April 1985", or "12 April" without a year. */
function readableBirthday(value: string): string {
  const yearless = value.startsWith('--');
  const [year, month, day] = yearless ? ['2000', value.slice(2, 4), value.slice(5, 7)] : value.split('-');
  const date = new Date(Number(year), Number(month) - 1, Number(day));
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString(undefined, yearless ? { day: 'numeric', month: 'long' } : { day: 'numeric', month: 'long', year: 'numeric' });
}

const kindLabel = (kind: string) => (kind ? kind.charAt(0).toUpperCase() + kind.slice(1) : '');

function EntryList({ label, kinds, entries, type, onChange }: {
  label: string; kinds: string[]; entries: Entry[]; type: string; onChange: (entries: Entry[]) => void;
}) {
  const set = (index: number, entry: Entry) => onChange(entries.map((e, i) => (i === index ? entry : e)));
  return (
    <div className="contact-field">
      <span className="contact-label">{label}</span>
      {entries.map((entry, index) => (
        <div className="contact-row" key={index}>
          <select aria-label={`${label} type`} value={entry.kind} onChange={(e) => set(index, { ...entry, kind: e.target.value })}>
            <option value="">Other</option>
            {kinds.map((kind) => <option key={kind} value={kind}>{kindLabel(kind)}</option>)}
            {entry.kind && !kinds.includes(entry.kind) && <option value={entry.kind}>{kindLabel(entry.kind)}</option>}
          </select>
          <input type={type} aria-label={label} value={entry.value} onChange={(e) => set(index, { ...entry, value: e.target.value })} />
          <button type="button" className="icon" aria-label={`Remove ${label.toLowerCase()}`} title="Remove" onClick={() => onChange(entries.filter((_, i) => i !== index))}><X size={14} /></button>
        </div>
      ))}
      <button type="button" className="link add-link" onClick={() => onChange([...entries, { kind: kinds[0], value: '' }])}><Plus size={13} />Add {label.toLowerCase()}</button>
    </div>
  );
}

function ContactEditor({ initial, books, book: initialBook, onCancel, onSave, busy }: {
  initial: ContactFields; books: Book[]; book: string | null;
  onCancel: () => void; onSave: (fields: ContactFields, book: string) => void; busy: boolean;
}) {
  const [fields, setFields] = useState<ContactFields>(initial);
  const writable = books.filter((b) => b.writable);
  const [book, setBook] = useState(initialBook ?? writable[0]?.id ?? '');
  const set = (change: Partial<ContactFields>) => setFields({ ...fields, ...change });
  const setAddress = (index: number, change: Partial<PostalAddress>) => set({ addresses: fields.addresses.map((a, i) => (i === index ? { ...a, ...change } : a)) });
  return (
    <form className="contact-editor" onSubmit={(e) => { e.preventDefault(); onSave(fields, book); }}>
      <div className="contact-grid">
        <label className="field"><span>First name</span><input autoFocus value={fields.given} onChange={(e) => set({ given: e.target.value })} /></label>
        <label className="field"><span>Last name</span><input value={fields.family} onChange={(e) => set({ family: e.target.value })} /></label>
        <label className="field wide"><span>Display name</span><input value={fields.full_name} placeholder={[fields.given, fields.family].filter(Boolean).join(' ') || 'From the first and last name'} onChange={(e) => set({ full_name: e.target.value })} /></label>
        <label className="field"><span>Company</span><input value={fields.org} onChange={(e) => set({ org: e.target.value })} /></label>
        <label className="field"><span>Job title</span><input value={fields.title} onChange={(e) => set({ title: e.target.value })} /></label>
      </div>
      <EntryList label="Email" type="email" kinds={['home', 'work']} entries={fields.emails} onChange={(emails) => set({ emails })} />
      <EntryList label="Phone" type="tel" kinds={['cell', 'home', 'work']} entries={fields.phones} onChange={(phones) => set({ phones })} />
      <div className="contact-field">
        <span className="contact-label">Address</span>
        {fields.addresses.map((address, index) => (
          <div className="contact-address" key={index}>
            <div className="contact-row">
              <select aria-label="Address type" value={address.kind} onChange={(e) => setAddress(index, { kind: e.target.value })}>
                <option value="">Other</option><option value="home">Home</option><option value="work">Work</option>
              </select>
              <input aria-label="Street" placeholder="Street" value={address.street} onChange={(e) => setAddress(index, { street: e.target.value })} />
              <button type="button" className="icon" aria-label="Remove address" title="Remove" onClick={() => set({ addresses: fields.addresses.filter((_, i) => i !== index) })}><X size={14} /></button>
            </div>
            <div className="contact-row indent">
              <input aria-label="Postcode" placeholder="Postcode" className="narrow" value={address.postcode} onChange={(e) => setAddress(index, { postcode: e.target.value })} />
              <input aria-label="City" placeholder="City" value={address.city} onChange={(e) => setAddress(index, { city: e.target.value })} />
            </div>
            <div className="contact-row indent">
              <input aria-label="Region" placeholder="Region" value={address.region} onChange={(e) => setAddress(index, { region: e.target.value })} />
              <input aria-label="Country" placeholder="Country" value={address.country} onChange={(e) => setAddress(index, { country: e.target.value })} />
            </div>
          </div>
        ))}
        <button type="button" className="link add-link" onClick={() => set({ addresses: [...fields.addresses, { kind: 'home', street: '', city: '', region: '', postcode: '', country: '' }] })}><Plus size={13} />Add address</button>
      </div>
      <div className="contact-grid">
        <label className="field"><span>Birthday</span><input type="date" value={fields.birthday.startsWith('--') ? '' : fields.birthday} onChange={(e) => set({ birthday: e.target.value })} /></label>
        {initialBook === null && writable.length > 1 && (
          <label className="field"><span>Address book</span>
            <select value={book} onChange={(e) => setBook(e.target.value)}>
              {writable.map((b) => <option key={b.id} value={b.id}>{b.displayname}{b.owner ? ` (${b.owner})` : ''}</option>)}
            </select>
          </label>
        )}
      </div>
      <label className="field"><span>Notes</span><textarea rows={3} value={fields.note} onChange={(e) => set({ note: e.target.value })} /></label>
      <div className="contact-buttons">
        <button type="button" className="secondary" onClick={onCancel}>Cancel</button>
        <button className="primary" disabled={busy || !book}>{busy ? 'Saving…' : 'Save'}</button>
      </div>
    </form>
  );
}

function ContactDetails({ contact, book, onEdit, onDelete, onWrite }: {
  contact: Contact; book: Book | undefined; onEdit: () => void; onDelete: () => void; onWrite: (address: string, name: string) => void;
}) {
  const name = displayName(contact);
  return (
    <div className="contact-details">
      <div className="contact-head">
        <div className="contact-avatar large" aria-hidden="true">{initials(contact)}</div>
        <div>
          <h2>{name}</h2>
          {(contact.title || contact.org) && <p className="muted">{[contact.title, contact.org].filter(Boolean).join(', ')}</p>}
          {book?.owner && <p className="muted small">In {book.displayname}, shared by {book.owner}{book.writable ? '' : ' (read only)'}</p>}
        </div>
      </div>
      {book?.writable && (
        <div className="contact-actions">
          <button className="secondary small-button" onClick={onEdit}><Pencil size={13} />Edit</button>
          <button className="secondary small-button danger-quiet" onClick={onDelete}><Trash2 size={13} />Delete</button>
        </div>
      )}
      <dl className="contact-list">
        {contact.emails.map((email, i) => (
          <div key={`e${i}`}><dt><Mail size={14} />{kindLabel(email.kind) || 'Email'}</dt><dd><button className="link" onClick={() => onWrite(email.value, name)}>{email.value}</button></dd></div>
        ))}
        {contact.phones.map((phone, i) => (
          <div key={`p${i}`}><dt><Phone size={14} />{kindLabel(phone.kind) || 'Phone'}</dt><dd><a href={`tel:${phone.value.replace(/[^\d+]/g, '')}`}>{phone.value}</a></dd></div>
        ))}
        {contact.addresses.map((a, i) => (
          <div key={`a${i}`}><dt><MapPin size={14} />{kindLabel(a.kind) || 'Address'}</dt><dd className="pre">{[a.street, [a.postcode, a.city].filter(Boolean).join(' '), a.region, a.country].filter(Boolean).join('\n')}</dd></div>
        ))}
        {contact.birthday && <div><dt><Cake size={14} />Birthday</dt><dd>{readableBirthday(contact.birthday)}</dd></div>}
      </dl>
      {contact.note && <p className="contact-note pre">{contact.note}</p>}
    </div>
  );
}

/** The user's contacts: search, view, add, edit and delete. */
export function ContactsDialog({ api, seed, onClose, onWrite }: {
  api: Api; seed: ContactSeed | null; onClose: () => void; onWrite: (address: string, name: string) => void;
}) {
  const [listing, setListing] = useState<Listing | null>(null);
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [editing, setEditing] = useState<{ fields: ContactFields; contact: Contact | null } | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const key = (c: Contact) => `${c.book}/${c.name}`;

  const load = () => api<Listing>('/api/addressbook').then((next) => { setListing(next); return next; });
  useEffect(() => {
    load().then((next) => {
      if (!seed) return;
      // An address already in the contacts opens that contact.
      const known = seed.email && next.contacts.find((c) => c.emails.some((e) => e.value.toLowerCase() === seed.email!.toLowerCase()));
      if (known) {
        setSelected(key(known));
        return;
      }
      const [given, ...rest] = (seed.name || '').trim().split(/\s+/);
      setEditing({ contact: null, fields: { ...emptyFields(), given: given || '', family: rest.join(' '), emails: seed.email ? [{ kind: '', value: seed.email }] : [] } });
    }).catch((err) => setError((err as Error).message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const shown = useMemo(() => (listing?.contacts ?? []).filter((c) => matches(c, query.trim())), [listing, query]);
  const current = listing?.contacts.find((c) => key(c) === selected) ?? null;
  const bookOf = (id: string) => listing?.books.find((b) => b.id === id);

  async function save(fields: ContactFields, book: string) {
    setBusy(true);
    setError('');
    try {
      const contact = editing?.contact;
      const saved = contact
        ? await api<Contact>(`/api/addressbook/${encodeURIComponent(contact.book)}/${encodeURIComponent(contact.name)}`, { method: 'PUT', body: JSON.stringify({ ...fields, etag: contact.etag }) })
        : await api<Contact>(`/api/addressbook/${encodeURIComponent(book)}`, { method: 'POST', body: JSON.stringify(fields) });
      await load();
      setEditing(null);
      setSelected(key(saved));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(contact: Contact) {
    if (!window.confirm(`Delete ${displayName(contact)}? It is removed from every device that syncs this address book.`)) return;
    setError('');
    try {
      await api(`/api/addressbook/${encodeURIComponent(contact.book)}/${encodeURIComponent(contact.name)}`, { method: 'DELETE', body: JSON.stringify({ etag: contact.etag }) });
      setSelected(null);
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const detailOpen = editing !== null || current !== null;
  const canAdd = (listing?.books ?? []).some((b) => b.writable);
  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && !editing && onClose()}>
      <section className={`dialog wide contacts-dialog ${detailOpen ? 'detail-open' : ''}`} role="dialog" aria-modal="true" aria-label="Contacts">
        <header>
          <h2><BookUser size={18} />Contacts</h2>
          <button type="button" className="icon" aria-label="Close" title="Close" autoFocus onClick={onClose}><X size={16} /></button>
        </header>
        {error && <p className="error" role="alert">{error}</p>}
        <div className="contacts-panes">
          <div className="contacts-list-pane">
            <div className="contacts-tools">
              <label className="contacts-search"><Search size={14} /><input aria-label="Search contacts" placeholder="Search" value={query} onChange={(e) => setQuery(e.target.value)} /></label>
              {canAdd && <button className="secondary small-button" onClick={() => { setSelected(null); setEditing({ contact: null, fields: emptyFields() }); }}><Plus size={13} />New</button>}
            </div>
            {listing === null ? <p className="muted">Loading…</p> : shown.length === 0 ? (
              <p className="muted contacts-empty">{query ? 'No contacts match.' : 'No contacts yet. Add one here, or sync them from your phone (CardDAV).'}</p>
            ) : (
              <ul className="contacts-list">
                {shown.map((contact) => (
                  <li key={key(contact)}>
                    <button className={selected === key(contact) ? 'active' : ''} onClick={() => { setEditing(null); setSelected(key(contact)); }}>
                      <span className="contact-avatar" aria-hidden="true">{initials(contact)}</span>
                      <span className="contact-summary"><strong>{displayName(contact)}</strong><small>{contact.emails[0]?.value || contact.phones[0]?.value || contact.org}</small></span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div className="contacts-detail-pane">
            {detailOpen && <button className="link contacts-back" onClick={() => { setEditing(null); setSelected(null); }}><ArrowLeft size={14} />All contacts</button>}
            {editing && listing ? (
              <ContactEditor key={editing.contact ? key(editing.contact) : 'new'} initial={editing.fields} books={listing.books}
                book={editing.contact ? editing.contact.book : null} busy={busy}
                onCancel={() => setEditing(null)} onSave={save} />
            ) : current ? (
              <ContactDetails contact={current} book={bookOf(current.book)} onWrite={onWrite}
                onEdit={() => setEditing({ contact: current, fields: { ...current } })} onDelete={() => remove(current)} />
            ) : (
              <p className="muted contacts-placeholder">Select a contact.</p>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
