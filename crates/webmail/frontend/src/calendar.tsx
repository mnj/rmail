// The calendar: week, month and agenda views over the user's CalDAV
// calendars (and those shared with them). Saving goes through the server's
// scheduling, so guests get invitations, updates and cancellations.

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, CalendarDays, ChevronLeft, ChevronRight, Clock, MapPin, Menu, Plus, RefreshCw, Repeat, Rss, Trash2, Users, X } from 'lucide-react';
import { Api } from './types';

type Details = {
  summary: string; location: string; description: string;
  start: number; end: number; all_day: boolean; timezone: string;
  repeat: 'none' | 'daily' | 'weekly' | 'monthly' | 'yearly' | 'custom';
  attendees: string[];
};
type Attendee = { address: string; name: string; status: string };
type CalEvent = {
  calendar: string; name: string; etag: string; uid: string;
  start: number; end: number; details: Details;
  organizer: string | null; attendee_details: Attendee[];
  my_status: string; editable: boolean; cancelled: boolean;
};
type Calendar = {
  id: string; displayname: string; color: string | null; owner?: string; writable: boolean;
  /** A subscribed feed (read-only). */
  subscription?: { url: string; refreshed_at: number | null; error: string | null };
};
type Listing = { calendars: Calendar[]; events: CalEvent[] };
type Mode = 'week' | 'month' | 'agenda';

const HOUR_PX = 44;
const palette = ['#6941c6', '#1570ef', '#079455', '#dc6803', '#d92d20', '#0e9384', '#c11574'];
const zone = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch { return 'UTC'; } })();

const startOfDay = (date: Date) => new Date(date.getFullYear(), date.getMonth(), date.getDate());
const addDays = (date: Date, days: number) => new Date(date.getFullYear(), date.getMonth(), date.getDate() + days);
/** Monday-based week start. */
const startOfWeek = (date: Date) => addDays(startOfDay(date), -((date.getDay() + 6) % 7));
const sameDay = (a: Date, b: Date) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();

/** An event's days as local dates: all-day events are stored as UTC dates. */
function eventDays(event: CalEvent): { first: Date; last: Date } {
  if (event.details.all_day) {
    const s = new Date(event.start * 1000);
    const e = new Date((event.end - 1) * 1000);
    return { first: new Date(s.getUTCFullYear(), s.getUTCMonth(), s.getUTCDate()), last: new Date(e.getUTCFullYear(), e.getUTCMonth(), e.getUTCDate()) };
  }
  const first = startOfDay(new Date(event.start * 1000));
  const last = startOfDay(new Date(Math.max(event.start, event.end - 1) * 1000));
  return { first, last };
}

const onDay = (event: CalEvent, day: Date) => {
  const { first, last } = eventDays(event);
  return first <= day && day <= last;
};

const time = (seconds: number) => new Date(seconds * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });

function colorOf(calendars: Calendar[], id: string): string {
  const index = calendars.findIndex((c) => c.id === id);
  return calendars[index]?.color?.slice(0, 7) || palette[Math.max(0, index) % palette.length];
}

/** Side-by-side columns for overlapping timed events of one day. */
function layout(events: CalEvent[]): Map<CalEvent, { column: number; columns: number }> {
  const sorted = [...events].sort((a, b) => a.start - b.start || b.end - a.end);
  const placed = new Map<CalEvent, { column: number; columns: number }>();
  let group: CalEvent[] = [];
  let groupEnd = 0;
  const flush = () => {
    const ends: number[] = [];
    for (const event of group) {
      let column = ends.findIndex((end) => end <= event.start);
      if (column === -1) { column = ends.length; ends.push(0); }
      ends[column] = event.end;
      placed.set(event, { column, columns: 0 });
    }
    for (const event of group) placed.get(event)!.columns = ends.length;
    group = [];
  };
  for (const event of sorted) {
    if (group.length && event.start >= groupEnd) flush();
    group.push(event);
    groupEnd = Math.max(groupEnd, event.end);
  }
  flush();
  return placed;
}

// ---------------------------------------------------------------------------
// Editor

const pad = (n: number) => String(n).padStart(2, '0');
const dateValue = (d: Date) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const timeValue = (d: Date) => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
const parseLocal = (date: string, clock: string) => {
  const [y, m, d] = date.split('-').map(Number);
  const [h, min] = (clock || '00:00').split(':').map(Number);
  return new Date(y, m - 1, d, h, min);
};
const utcDay = (date: string) => { const [y, m, d] = date.split('-').map(Number); return Date.UTC(y, m - 1, d) / 1000; };
const fromUtcDay = (seconds: number) => { const d = new Date(seconds * 1000); return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`; };

type Draft = { calendar: string; name: string | null; etag: string | null; details: Details };

function EventEditor({ api, draft, calendars, onClose, onSaved }: { api: Api; draft: Draft; calendars: Calendar[]; onClose: () => void; onSaved: (message: string) => void }) {
  const d = draft.details;
  const start = new Date(d.start * 1000);
  const end = new Date(d.end * 1000);
  const [summary, setSummary] = useState(d.summary);
  const [allDay, setAllDay] = useState(d.all_day);
  const [startDate, setStartDate] = useState(d.all_day ? fromUtcDay(d.start) : dateValue(start));
  const [startTime, setStartTime] = useState(d.all_day ? '09:00' : timeValue(start));
  const [endDate, setEndDate] = useState(d.all_day ? fromUtcDay(d.end - 86_400) : dateValue(end));
  const [endTime, setEndTime] = useState(d.all_day ? '10:00' : timeValue(end));
  const [repeat, setRepeat] = useState(d.repeat);
  const [location, setLocation] = useState(d.location);
  const [guests, setGuests] = useState(d.attendees.join(', '));
  const [description, setDescription] = useState(d.description);
  const [rooms, setRooms] = useState<{ address: string; kind: 'room' | 'equipment' }[]>([]);
  useEffect(() => { api<{ address: string; kind: 'room' | 'equipment' }[]>('/api/resources').then(setRooms).catch(() => setRooms([])); }, [api]);
  const guestList = guests.split(/[,;\s]+/).map((g) => g.trim().toLowerCase()).filter(Boolean);
  const addGuest = (address: string) => { if (!guestList.includes(address)) setGuests([...guestList, address].join(', ')); };
  const [calendar, setCalendar] = useState(draft.calendar);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const writable = calendars.filter((c) => c.writable);

  async function save(event: React.FormEvent) {
    event.preventDefault();
    const times = allDay
      ? { start: utcDay(startDate), end: utcDay(endDate) + 86_400 }
      : { start: parseLocal(startDate, startTime).getTime() / 1000, end: parseLocal(endDate, endTime).getTime() / 1000 };
    if (times.end <= times.start) { setError('The event must end after it starts.'); return; }
    const attendees = guests.split(/[,;\s]+/).map((g) => g.trim()).filter(Boolean);
    const body = { summary, location, description, all_day: allDay, timezone: d.timezone && draft.name && !allDay && times.start === d.start ? d.timezone : zone, repeat, attendees, ...times, ...(draft.etag ? { etag: draft.etag } : {}) };
    setBusy(true);
    setError('');
    try {
      const path = draft.name ? `/api/events/${encodeURIComponent(draft.calendar)}/${encodeURIComponent(draft.name)}` : `/api/events/${encodeURIComponent(calendar)}`;
      await api(path, { method: draft.name ? 'PUT' : 'POST', body: JSON.stringify(body) });
      const invited = attendees.length > 0;
      onSaved(draft.name ? (invited ? 'Event updated; guests were told.' : 'Event updated.') : (invited ? 'Event added; invitations sent.' : 'Event added.'));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && onClose()}>
      <form className="dialog event-editor" role="dialog" aria-modal="true" aria-label={draft.name ? 'Edit event' : 'New event'} onSubmit={save}>
        <header><h2>{draft.name ? 'Edit event' : 'New event'}</h2><button type="button" className="icon" aria-label="Close" title="Close" onClick={onClose}><X size={16} /></button></header>
        <label className="field"><span>Title</span><input autoFocus value={summary} maxLength={500} placeholder="Meeting" onChange={(e) => setSummary(e.target.value)} /></label>
        <label className="check-row tight"><input type="checkbox" checked={allDay} onChange={(e) => setAllDay(e.target.checked)} /><span>All day</span></label>
        <div className="event-times">
          <label className="field"><span>Starts</span><span className="event-time-row"><input type="date" value={startDate} onChange={(e) => { setStartDate(e.target.value); if (e.target.value > endDate) setEndDate(e.target.value); }} />{!allDay && <input type="time" aria-label="Start time" value={startTime} onChange={(e) => setStartTime(e.target.value)} />}</span></label>
          <label className="field"><span>Ends</span><span className="event-time-row"><input type="date" value={endDate} min={startDate} onChange={(e) => setEndDate(e.target.value)} />{!allDay && <input type="time" aria-label="End time" value={endTime} onChange={(e) => setEndTime(e.target.value)} />}</span></label>
        </div>
        <div className="settings-grid two">
          <label className="field"><span>Repeat</span>
            <select value={repeat} onChange={(e) => setRepeat(e.target.value as Details['repeat'])}>
              <option value="none">Does not repeat</option><option value="daily">Every day</option><option value="weekly">Every week</option>
              <option value="monthly">Every month</option><option value="yearly">Every year</option>
              {d.repeat === 'custom' && <option value="custom">As set in another app</option>}
            </select>
          </label>
          {!draft.name && writable.length > 1 ? (
            <label className="field"><span>Calendar</span>
              <select value={calendar} onChange={(e) => setCalendar(e.target.value)}>
                {writable.map((c) => <option key={c.id} value={c.id}>{c.displayname}{c.owner ? ` (${c.owner})` : ''}</option>)}
              </select>
            </label>
          ) : <span />}
        </div>
        <label className="field"><span>Place</span><input value={location} maxLength={500} onChange={(e) => setLocation(e.target.value)} /></label>
        <label className="field"><span>Guests</span><input value={guests} placeholder="name@example.com, …" onChange={(e) => setGuests(e.target.value)} /></label>
        {rooms.length > 0 && (
          <label className="field"><span>Book a room or equipment</span>
            <select value="" onChange={(e) => e.target.value && addGuest(e.target.value)}>
              <option value="">Choose…</option>
              {rooms.filter((r) => !guestList.includes(r.address)).map((r) => <option key={r.address} value={r.address}>{r.address.split('@')[0]} ({r.kind === 'room' ? 'room' : 'equipment'})</option>)}
            </select>
          </label>
        )}
        {guests.trim() && <p className="dialog-hint">Guests get an invitation by email (or straight in their calendar on this server), and an update or cancellation when you change or delete the event.</p>}
        <label className="field"><span>Notes</span><textarea rows={3} value={description} onChange={(e) => setDescription(e.target.value)} /></label>
        {error && <p className="error" role="alert">{error}</p>}
        <footer><button type="button" className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button></footer>
      </form>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Subscriptions

function SubscribeDialog({ api, onClose, onDone }: { api: Api; onClose: () => void; onDone: (message: string) => void }) {
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const made = await api<{ events: number }>('/api/subscriptions', { method: 'POST', body: JSON.stringify({ url, name }) });
      onDone(`Subscribed: ${made.events} event${made.events === 1 ? '' : 's'}.`);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && onClose()}>
      <form className="dialog small" role="dialog" aria-modal="true" aria-label="Subscribe to a calendar" onSubmit={submit}>
        <header><h2>Subscribe to a calendar</h2><button type="button" className="icon" aria-label="Close" title="Close" onClick={onClose}><X size={16} /></button></header>
        <p className="dialog-intro">Public holidays, a sports schedule, a team's published calendar: paste its webcal or https address. It is read-only, refreshed every few hours, and shows in your calendar apps too.</p>
        <label className="field"><span>Address</span><input autoFocus type="url" inputMode="url" placeholder="webcal://…/calendar.ics" value={url} onChange={(e) => setUrl(e.target.value)} /></label>
        <label className="field"><span>Name (optional)</span><input maxLength={100} value={name} onChange={(e) => setName(e.target.value)} /></label>
        {error && <p className="error" role="alert">{error}</p>}
        <footer><button type="button" className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={busy || !url.trim()}>{busy ? 'Fetching…' : 'Subscribe'}</button></footer>
      </form>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Event details

const statusWords: Record<string, string> = { accepted: 'Going', declined: 'Not going', tentative: 'Maybe', 'needs-action': 'No answer yet' };

function EventPopup({ event, calendar, color, onClose, onEdit, onDelete }: {
  event: CalEvent; calendar: Calendar | undefined; color: string; onClose: () => void; onEdit: () => void; onDelete: () => void;
}) {
  const d = event.details;
  const { first, last } = eventDays(event);
  const dateText = (date: Date) => date.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' });
  const when = d.all_day
    ? (sameDay(first, last) ? `${dateText(first)}, all day` : `${dateText(first)} – ${dateText(last)}`)
    : sameDay(first, last)
      ? `${dateText(first)}, ${time(event.start)}–${time(event.end)}`
      : `${dateText(first)} ${time(event.start)} – ${dateText(last)} ${time(event.end)}`;
  const guests = event.attendee_details.filter((a) => a.address !== event.organizer);
  return (
    <div className="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()} onKeyDown={(e) => e.key === 'Escape' && onClose()}>
      <section className="dialog small event-popup" role="dialog" aria-modal="true" aria-label={d.summary || 'Event'}>
        <header>
          <h2 className={event.cancelled ? 'cancelled' : ''}>{d.summary || '(no title)'}</h2>
          <button type="button" className="icon" aria-label="Close" title="Close" autoFocus onClick={onClose}><X size={16} /></button>
        </header>
        <div className="event-facts">
          <div><Clock size={14} />{when}{event.cancelled && <strong className="danger-text"> · Cancelled</strong>}</div>
          {d.repeat !== 'none' && <div><Repeat size={14} />{{ daily: 'Every day', weekly: 'Every week', monthly: 'Every month', yearly: 'Every year', custom: 'Repeats', none: '' }[d.repeat]}</div>}
          {d.location && <div><MapPin size={14} />{d.location}</div>}
          {calendar && <div><span className="calendar-dot" style={{ background: color }} />{calendar.displayname}{calendar.owner ? `, shared by ${calendar.owner}` : ''}</div>}
          {guests.length > 0 && (
            <div className="event-guests"><Users size={14} />
              <ul>{guests.map((g) => <li key={g.address}><span>{g.name || g.address}</span><small className="muted">{statusWords[g.status] ?? g.status}</small></li>)}</ul>
            </div>
          )}
          {event.my_status && <p className="dialog-hint">You are invited{event.organizer ? ` by ${event.organizer}` : ''}: {statusWords[event.my_status] ?? event.my_status}. Answer from the invitation in your mail.</p>}
        </div>
        {d.description && <p className="event-description pre">{d.description}</p>}
        {event.editable && (
          <footer>
            <button className="secondary danger-quiet" onClick={onDelete}><Trash2 size={14} />Delete</button>
            <span className="spacer" />
            <button className="primary" onClick={onEdit}>Edit</button>
          </footer>
        )}
      </section>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Views

function WeekView({ days, events, calendars, onOpen, onCreate }: {
  days: Date[]; events: CalEvent[]; calendars: Calendar[]; onOpen: (event: CalEvent) => void; onCreate: (start: Date, allDay: boolean) => void;
}) {
  const scroller = useRef<HTMLDivElement>(null);
  const today = startOfDay(new Date());
  const weekKey = days[0]?.toISOString();
  // This week opens an hour before now; another at its first event, or 07:00.
  useEffect(() => {
    if (!scroller.current) return;
    const timedEvents = events.filter((e) => !e.details.all_day);
    const first = timedEvents.length ? Math.min(...timedEvents.map((e) => new Date(e.start * 1000).getHours())) : 7;
    const hour = days.some((day) => sameDay(day, today)) ? new Date().getHours() - 1 : Math.min(7, first);
    scroller.current.scrollTop = Math.max(0, hour) * HOUR_PX;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [weekKey]);
  const [now, setNow] = useState(new Date());
  useEffect(() => { const timer = window.setInterval(() => setNow(new Date()), 60_000); return () => window.clearInterval(timer); }, []);
  const allDay = (day: Date) => events.filter((e) => (e.details.all_day || e.end - e.start >= 86_400) && onDay(e, day));
  const timed = (day: Date) => events.filter((e) => !e.details.all_day && e.end - e.start < 86_400 && onDay(e, day));
  return (
    <div className="week" style={{ '--days': days.length } as React.CSSProperties}>
      <div className="week-head">
        <span />
        {days.map((day) => (
          <div key={day.toISOString()} className={`week-day-name ${sameDay(day, today) ? 'today' : ''}`}>
            <small>{day.toLocaleDateString(undefined, { weekday: 'short' })}</small><strong>{day.getDate()}</strong>
          </div>
        ))}
        <span className="muted small all-day-label">All day</span>
        {days.map((day) => (
          <div key={`a${day.toISOString()}`} className="week-all-day" onDoubleClick={() => onCreate(day, true)}>
            {allDay(day).map((event) => (
              <button key={`${event.name}${event.start}`} className={`chip ${event.cancelled ? 'cancelled' : ''}`} style={{ '--event': colorOf(calendars, event.calendar) } as React.CSSProperties} onClick={() => onOpen(event)}>{event.details.summary || '(no title)'}</button>
            ))}
          </div>
        ))}
      </div>
      <div className="week-body" ref={scroller}>
        <div className="week-hours">{Array.from({ length: 24 }, (_, h) => <span key={h}>{h ? `${pad(h)}:00` : ''}</span>)}</div>
        {days.map((day) => {
          const list = timed(day);
          const placed = layout(list);
          return (
            <div key={day.toISOString()} className="week-column" onClick={(e) => {
              if (e.target !== e.currentTarget) return;
              const minutes = Math.floor(((e.nativeEvent.offsetY / HOUR_PX) * 60) / 30) * 30;
              onCreate(new Date(day.getFullYear(), day.getMonth(), day.getDate(), Math.floor(minutes / 60), minutes % 60), false);
            }}>
              {sameDay(day, today) && <div className="now-line" style={{ top: ((now.getHours() * 60 + now.getMinutes()) / 60) * HOUR_PX }} />}
              {list.map((event) => {
                const dayStart = day.getTime() / 1000;
                const top = Math.max(0, (event.start - dayStart) / 3600) * HOUR_PX;
                const bottom = Math.min(24, (event.end - dayStart) / 3600) * HOUR_PX;
                const { column, columns } = placed.get(event)!;
                return (
                  <button key={`${event.name}${event.start}`} className={`week-event ${event.cancelled ? 'cancelled' : ''} ${event.my_status === 'needs-action' ? 'pending' : ''}`}
                    style={{ top, height: Math.max(20, bottom - top - 2), left: `${(column / columns) * 100}%`, width: `calc(${100 / columns}% - 3px)`, '--event': colorOf(calendars, event.calendar) } as React.CSSProperties}
                    onClick={() => onOpen(event)}>
                    <strong>{event.details.summary || '(no title)'}</strong>
                    <small>{time(event.start)}{event.details.location ? ` · ${event.details.location}` : ''}</small>
                  </button>
                );
              })}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function MonthView({ month, events, calendars, onOpen, onCreate }: {
  month: Date; events: CalEvent[]; calendars: Calendar[]; onOpen: (event: CalEvent) => void; onCreate: (start: Date, allDay: boolean) => void;
}) {
  const first = startOfWeek(new Date(month.getFullYear(), month.getMonth(), 1));
  const days = Array.from({ length: 42 }, (_, i) => addDays(first, i));
  const today = startOfDay(new Date());
  return (
    <div className="month">
      {days.slice(0, 7).map((day) => <div key={`h${day.getDay()}`} className="month-weekday">{day.toLocaleDateString(undefined, { weekday: 'short' })}</div>)}
      {days.map((day) => {
        const list = events.filter((e) => onDay(e, day));
        return (
          <div key={day.toISOString()} className={`month-day ${day.getMonth() !== month.getMonth() ? 'other' : ''} ${sameDay(day, today) ? 'today' : ''}`}
            onDoubleClick={(e) => { if (e.target === e.currentTarget) onCreate(new Date(day.getFullYear(), day.getMonth(), day.getDate(), 9), false); }}>
            <span className="month-date">{day.getDate()}</span>
            {list.slice(0, 3).map((event) => (
              <button key={`${event.name}${event.start}`} className={`chip ${event.details.all_day ? '' : 'timed'} ${event.cancelled ? 'cancelled' : ''}`} style={{ '--event': colorOf(calendars, event.calendar) } as React.CSSProperties} onClick={() => onOpen(event)}>
                {!event.details.all_day && <small>{time(event.start)}</small>}{event.details.summary || '(no title)'}
              </button>
            ))}
            {list.length > 3 && <small className="muted">{list.length - 3} more</small>}
          </div>
        );
      })}
    </div>
  );
}

function AgendaView({ from, events, calendars, onOpen }: { from: Date; events: CalEvent[]; calendars: Calendar[]; onOpen: (event: CalEvent) => void }) {
  const days = Array.from({ length: 31 }, (_, i) => addDays(from, i)).map((day) => ({ day, list: events.filter((e) => onDay(e, day)) })).filter((d) => d.list.length);
  if (days.length === 0) return <p className="muted agenda-empty">Nothing in the next month.</p>;
  return (
    <div className="agenda">
      {days.map(({ day, list }) => (
        <section key={day.toISOString()}>
          <h3 className={sameDay(day, new Date()) ? 'today' : ''}>{day.toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long' })}</h3>
          {list.map((event) => (
            <button key={`${event.name}${event.start}`} className={`agenda-event ${event.cancelled ? 'cancelled' : ''}`} onClick={() => onOpen(event)}>
              <span className="calendar-dot" style={{ background: colorOf(calendars, event.calendar) }} />
              <span className="agenda-time">{event.details.all_day ? 'All day' : `${time(event.start)}–${time(event.end)}`}</span>
              <span className="agenda-title"><strong>{event.details.summary || '(no title)'}</strong>{event.details.location && <small className="muted">{event.details.location}</small>}</span>
            </button>
          ))}
        </section>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------

export function CalendarView({ api, onShowFolders, flash }: { api: Api; onShowFolders: () => void; flash: (text: string) => void }) {
  const narrow = typeof window !== 'undefined' && window.matchMedia?.('(max-width: 860px)').matches;
  const [mode, setMode] = useState<Mode>(narrow ? 'agenda' : 'week');
  const [anchor, setAnchor] = useState(startOfDay(new Date()));
  const [listing, setListing] = useState<Listing | null>(null);
  const [error, setError] = useState('');
  const [open, setOpen] = useState<CalEvent | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [hidden, setHidden] = useState<string[]>([]);
  const [subscribing, setSubscribing] = useState(false);

  const range = useMemo(() => {
    if (mode === 'week') { const from = startOfWeek(anchor); return { from, to: addDays(from, 7) }; }
    if (mode === 'month') { const from = startOfWeek(new Date(anchor.getFullYear(), anchor.getMonth(), 1)); return { from, to: addDays(from, 42) }; }
    return { from: anchor, to: addDays(anchor, 31) };
  }, [mode, anchor]);

  const load = useCallback(() => {
    // A day either side, so all-day events (UTC dates) are found in any zone.
    const from = Math.floor(range.from.getTime() / 1000) - 86_400;
    const to = Math.floor(range.to.getTime() / 1000) + 86_400;
    return api<Listing>(`/api/events?from=${from}&to=${to}`).then(setListing).catch((err) => setError((err as Error).message));
  }, [api, range]);
  useEffect(() => { load(); }, [load]);

  const calendars = listing?.calendars ?? [];
  const events = (listing?.events ?? []).filter((e) => !hidden.includes(e.calendar));
  const writable = calendars.filter((c) => c.writable);

  const move = (direction: number) => {
    if (mode === 'week') setAnchor(addDays(anchor, 7 * direction));
    else if (mode === 'month') setAnchor(new Date(anchor.getFullYear(), anchor.getMonth() + direction, 1));
    else setAnchor(addDays(anchor, 31 * direction));
  };
  const title = mode === 'month'
    ? anchor.toLocaleDateString(undefined, { month: 'long', year: 'numeric' })
    : mode === 'week'
      ? (() => { const end = addDays(range.from, 6); return `${range.from.toLocaleDateString(undefined, { day: 'numeric', month: 'short' })} – ${end.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })}`; })()
      : `From ${anchor.toLocaleDateString(undefined, { day: 'numeric', month: 'long' })}`;

  const create = (start: Date, allDay: boolean) => {
    if (!writable.length) return;
    const begin = allDay ? Date.UTC(start.getFullYear(), start.getMonth(), start.getDate()) / 1000 : start.getTime() / 1000;
    setDraft({ calendar: writable[0].id, name: null, etag: null, details: { summary: '', location: '', description: '', start: begin, end: begin + (allDay ? 86_400 : 3_600), all_day: allDay, timezone: zone, repeat: 'none', attendees: [] } });
  };
  const newEvent = () => {
    const now = new Date();
    create(new Date(anchor.getFullYear(), anchor.getMonth(), anchor.getDate(), Math.min(23, now.getHours() + 1)), false);
  };

  async function remove(event: CalEvent) {
    const guests = event.attendee_details.some((a) => a.address !== event.organizer);
    const series = event.details.repeat !== 'none' ? ' and every other time it repeats' : '';
    if (!window.confirm(`Delete "${event.details.summary || 'this event'}"${series}?${guests ? ' Guests are told it is cancelled.' : ''}`)) return;
    try {
      await api(`/api/events/${encodeURIComponent(event.calendar)}/${encodeURIComponent(event.name)}`, { method: 'DELETE', body: JSON.stringify({ etag: event.etag }) });
      setOpen(null);
      flash(guests ? 'Event deleted; guests were told.' : 'Event deleted.');
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function refreshFeed(calendar: Calendar) {
    try {
      const done = await api<{ stored: number; removed: number }>(`/api/subscriptions/${encodeURIComponent(calendar.id)}/refresh`, { method: 'POST' });
      flash(`${calendar.displayname} refreshed${done.stored || done.removed ? ` (${done.stored} new or changed, ${done.removed} removed)` : ''}.`);
    } catch (err) {
      setError((err as Error).message);
    }
    load();
  }

  async function unsubscribe(calendar: Calendar) {
    if (!window.confirm(`Unsubscribe from ${calendar.displayname}? Its events disappear from your calendars.`)) return;
    try {
      await api(`/api/subscriptions/${encodeURIComponent(calendar.id)}`, { method: 'DELETE' });
      flash(`Unsubscribed from ${calendar.displayname}.`);
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const days = Array.from({ length: 7 }, (_, i) => addDays(range.from, i));
  return (
    <section className="calendar-pane" aria-label="Calendar">
      <header className="calendar-bar">
        <button className="icon mobile-only" aria-label="Folders" title="Folders" onClick={onShowFolders}><Menu size={18} /></button>
        <button className="secondary small-button" onClick={() => setAnchor(mode === 'month' ? new Date(new Date().getFullYear(), new Date().getMonth(), 1) : startOfDay(new Date()))}>Today</button>
        <button className="icon" aria-label="Previous" title="Previous" onClick={() => move(-1)}><ChevronLeft size={18} /></button>
        <button className="icon" aria-label="Next" title="Next" onClick={() => move(1)}><ChevronRight size={18} /></button>
        <h2>{title}</h2>
        <span className="spacer" />
        <div className="segmented" role="tablist" aria-label="View">
          {(['week', 'month', 'agenda'] as Mode[]).map((m) => <button key={m} role="tab" aria-selected={mode === m} className={mode === m ? 'active' : ''} onClick={() => setMode(m)}>{m[0].toUpperCase() + m.slice(1)}</button>)}
        </div>
        {writable.length > 0 && <button className="primary small-button" onClick={newEvent}><Plus size={14} />New</button>}
      </header>
      {listing && (
        <div className="calendar-filters">
          {calendars.map((c) => (
            <span key={c.id} className="calendar-filter">
              <label>
                <input type="checkbox" checked={!hidden.includes(c.id)} onChange={(e) => setHidden(e.target.checked ? hidden.filter((h) => h !== c.id) : [...hidden, c.id])} />
                <span className="calendar-dot" style={{ background: colorOf(calendars, c.id) }} />{c.displayname}{c.owner ? <small className="muted"> ({c.owner})</small> : null}
              </label>
              {c.subscription && <>
                {c.subscription.error
                  ? <span className="feed-error" title={`Last refresh failed: ${c.subscription.error}`}><AlertTriangle size={13} /></span>
                  : <span className="muted" title={`Subscribed to ${c.subscription.url}`}><Rss size={12} /></span>}
                <button type="button" className="icon tiny" aria-label={`Refresh ${c.displayname}`} title="Refresh now" onClick={() => refreshFeed(c)}><RefreshCw size={12} /></button>
                <button type="button" className="icon tiny" aria-label={`Unsubscribe from ${c.displayname}`} title="Unsubscribe" onClick={() => unsubscribe(c)}><X size={12} /></button>
              </>}
            </span>
          ))}
          <button type="button" className="link add-link" onClick={() => setSubscribing(true)}><Rss size={13} />Subscribe…</button>
        </div>
      )}
      {error && <p className="error calendar-error" role="alert">{error}</p>}
      <div className="calendar-body">
        {listing === null ? <p className="muted agenda-empty"><CalendarDays size={16} /> Loading…</p>
          : mode === 'week' ? <WeekView days={days} events={events} calendars={calendars} onOpen={setOpen} onCreate={create} />
          : mode === 'month' ? <MonthView month={anchor} events={events} calendars={calendars} onOpen={setOpen} onCreate={create} />
          : <AgendaView from={anchor} events={events} calendars={calendars} onOpen={setOpen} />}
      </div>
      {open && <EventPopup event={open} calendar={calendars.find((c) => c.id === open.calendar)} color={colorOf(calendars, open.calendar)} onClose={() => setOpen(null)} onDelete={() => remove(open)}
        onEdit={() => { setDraft({ calendar: open.calendar, name: open.name, etag: open.etag, details: open.details }); setOpen(null); }} />}
      {subscribing && <SubscribeDialog api={api} onClose={() => setSubscribing(false)} onDone={(message) => { setSubscribing(false); flash(message); load(); }} />}
      {draft && <EventEditor api={api} draft={draft} calendars={calendars} onClose={() => setDraft(null)} onSaved={(message) => { setDraft(null); flash(message); load(); }} />}
    </section>
  );
}
