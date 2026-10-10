// AI writing suggestions while composing (opt-in, see compose settings).
//
// Ghost text: after a short pause in typing, the text around the caret goes
// to webmail's server (/api/compose/assist), which asks the AI service the
// admin configured for a short continuation. It is drawn in grey after the
// caret in an overlay, never inside the document, so drafts, undo and
// getHTML() stay clean until it is accepted. Tab (or a tap on it) accepts;
// Esc, moving the caret or typing something else dismisses it. Every
// keystroke aborts a pending request, and the server then drops its request
// to the provider too.
//
// Only the draft (trimmed around the caret), the subject and a quoted
// original are sent; the server trims again.

import type Squire from 'squire-rte';
import { Api, ApiError } from './types';
import { EditorPlugin, contentText } from './editor';

/** Pause in typing before a suggestion is asked for. */
const PAUSE_MS = 400;
/** What the browser sends; the server keeps less (2000/500/1500). */
const MAX_BEFORE = 3000;
const MAX_AFTER = 800;
const MAX_QUOTED = 2000;
/** Back off this long after the server says "too many" or a failure. */
const BACKOFF_MS = 15_000;

export type RewriteStyle = 'shorter' | 'formal' | 'friendly' | 'grammar';

export const REWRITE_STYLES: [RewriteStyle, string][] = [
  ['shorter', 'Shorter'],
  ['formal', 'More formal'],
  ['friendly', 'Friendlier'],
  ['grammar', 'Fix spelling and grammar'],
];

type AssistAnswer = { text?: string; error?: string; message?: string };

/** Ask the server; resolves to the text, throws an Error with a user-facing message. */
export async function assist(api: Api, body: Record<string, string>, signal?: AbortSignal): Promise<string> {
  const answer = await api<AssistAnswer>('/api/compose/assist', { method: 'POST', body: JSON.stringify(body), signal });
  if (answer.error) throw new Error(answer.message || 'The writing assistant failed.');
  return answer.text || '';
}

/** The draft around the caret; `null` when no suggestion fits there. */
export type DraftContext = { before: string; after: string; quoted: string };

/** Where the caret is and how the text there looks, in viewport coordinates. */
export type CaretBox = {
  caret: DOMRect;
  /** Left edge and width of the text column (where wrapped lines start). */
  left: number;
  width: number;
  /** Element whose font the ghost copies. */
  styleFrom: Element;
  /** Visible part of the editing area; no ghost outside it. */
  clip: DOMRect;
};

type Host = {
  /** Positioned element the overlay is placed in (not the editable area). */
  container: HTMLElement;
  /** Whether the user is still in the editing area; answers that arrive later are dropped. */
  focused: () => boolean;
  context: () => DraftContext | null;
  caretBox: () => CaretBox | null;
  insert: (text: string) => void;
};

/** A reply's quote and the signature are not part of what the user is writing. */
const NOT_DRAFT = 'blockquote[type="cite"], [data-rmail-signature]';

/** Lines quoted with ">" (a plain-text reply) and the "-- " signature are not draft text. */
function splitPlain(text: string): { draft: string; quoted: string } {
  const lines = text.split('\n');
  const signature = lines.indexOf('-- ');
  const kept = signature >= 0 ? lines.slice(0, signature) : lines;
  return {
    draft: kept.filter((line) => !line.startsWith('>')).join('\n'),
    quoted: kept.filter((line) => line.startsWith('>')).map((line) => line.replace(/^>+ ?/, '')).join('\n'),
  };
}

/** Whether the caret sits at the end of a line with some text before it on that line. */
function fits(before: string, after: string): boolean {
  const line = before.slice(before.lastIndexOf('\n') + 1);
  const rest = after.slice(0, after.indexOf('\n') < 0 ? after.length : after.indexOf('\n'));
  return line.trim().length >= 2 && rest.trim() === '' && before.trim().length >= 3;
}

class Ghost {
  readonly element: HTMLDivElement;
  text = '';

  constructor(container: HTMLElement, onAccept: () => void) {
    this.element = document.createElement('div');
    this.element.className = 'ghost-text';
    this.element.setAttribute('aria-hidden', 'true');
    this.element.hidden = true;
    // A tap accepts on touch screens (there is no Tab key); keep the caret.
    this.element.addEventListener('mousedown', (event) => { event.preventDefault(); onAccept(); });
    container.appendChild(this.element);
  }

  show(text: string, box: CaretBox, container: HTMLElement) {
    this.text = text;
    const { caret, clip } = box;
    if (caret.top < clip.top || caret.bottom > clip.bottom + 1) { this.hide(); return; }
    const origin = container.getBoundingClientRect();
    const style = getComputedStyle(box.styleFrom);
    const fontSize = parseFloat(style.fontSize) || 14;
    const lineHeight = style.lineHeight === 'normal' ? fontSize * 1.3 : parseFloat(style.lineHeight);
    const element = this.element;
    for (const name of ['fontFamily', 'fontSize', 'fontWeight', 'fontStyle', 'letterSpacing'] as const) element.style[name] = style[name];
    element.style.lineHeight = `${lineHeight}px`;
    // The first line starts at the caret; wrapped lines start at the text
    // column's left edge, like the text they continue.
    element.style.left = `${box.left - origin.left}px`;
    element.style.width = `${box.width}px`;
    element.style.textIndent = `${Math.max(0, caret.left - box.left)}px`;
    element.style.top = `${caret.top - origin.top - (lineHeight - caret.height) / 2}px`;
    element.style.maxHeight = `${Math.max(lineHeight, clip.bottom - caret.top)}px`;
    const label = document.createElement('span');
    label.className = 'ghost-hint';
    // Phones have no Tab key; the suggestion itself is the button there.
    label.textContent = window.matchMedia('(pointer: coarse)').matches ? 'Tap' : 'Tab';
    element.replaceChildren(document.createTextNode(text), label);
    element.hidden = false;
  }

  hide() {
    this.text = '';
    this.element.hidden = true;
    this.element.replaceChildren();
  }

  get visible() {
    return !this.element.hidden && this.text !== '';
  }
}

/**
 * Ghost-text suggestions for one editing area. `subject` is read when a
 * suggestion is asked for. Returns the controller the host feeds events to.
 */
function createAssistant(api: Api, subject: () => string, host: Host) {
  const ghost = new Ghost(host.container, () => accept());
  let timer: number | undefined;
  let request: AbortController | null = null;
  let pausedUntil = 0;
  let stopped = false;
  /** A typed character that matched the ghost's first one. */
  let typedAhead = false;
  /** The next input is our own insertion. */
  let accepting = false;

  function cancel() {
    window.clearTimeout(timer);
    request?.abort();
    request = null;
  }

  function dismiss() {
    cancel();
    ghost.hide();
  }

  async function ask() {
    if (stopped || Date.now() < pausedUntil || !host.focused()) return;
    const context = host.context();
    if (!context || !fits(context.before, context.after)) return;
    const controller = new AbortController();
    request = controller;
    try {
      const text = await assist(api, {
        kind: 'continue',
        subject: subject().slice(0, 300),
        before: context.before.slice(-MAX_BEFORE),
        after: context.after.slice(0, MAX_AFTER),
        quoted: context.quoted.slice(0, MAX_QUOTED),
      }, controller.signal);
      if (controller.signal.aborted || request !== controller) return;
      request = null;
      const box = host.focused() ? host.caretBox() : null;
      if (text.trim() && box) ghost.show(text, box, host.container);
    } catch (error) {
      if (controller.signal.aborted) return;
      request = null;
      const status = error instanceof ApiError ? error.status : 0;
      // Turned off on the server or for this user: stop asking in this window.
      if (status === 403 || status === 409) stopped = true;
      else pausedUntil = Date.now() + BACKOFF_MS;
    }
  }

  function accept(): boolean {
    if (!ghost.visible) return false;
    const text = ghost.text;
    dismiss();
    accepting = true;
    host.insert(text);
    accepting = false;
    return true;
  }

  return {
    get visible() { return ghost.visible; },
    accept,
    dismiss,
    /** The text changed (typing, paste, undo). */
    changed() {
      if (accepting) return;
      if (typedAhead && ghost.visible) {
        typedAhead = false;
        const rest = ghost.text.slice(1);
        const box = host.caretBox();
        if (rest.trim() && box) { ghost.show(rest, box, host.container); return; }
      }
      typedAhead = false;
      dismiss();
      timer = window.setTimeout(ask, PAUSE_MS);
    },
    /** A key went down; returns true when it was handled here. */
    keydown(event: KeyboardEvent): boolean {
      if (event.isComposing) return false;
      if (event.key === 'Escape' && ghost.visible) {
        event.preventDefault();
        dismiss();
        return true;
      }
      if (event.key === 'Tab' && !event.shiftKey && ghost.visible) {
        event.preventDefault();
        accept();
        return true;
      }
      if (['Shift', 'Control', 'Alt', 'Meta', 'CapsLock'].includes(event.key)) return false;
      // Typing the ghost's next character keeps the rest of it.
      if (ghost.visible && event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey && ghost.text.startsWith(event.key)) {
        typedAhead = true;
        cancel();
        return false;
      }
      dismiss();
      return false;
    },
    destroy() {
      dismiss();
      stopped = true;
      ghost.element.remove();
    },
  };
}

/** The visible part of an element, in viewport coordinates. */
function visibleRect(element: HTMLElement): DOMRect {
  const rect = element.getBoundingClientRect();
  return new DOMRect(rect.left + element.clientLeft, rect.top + element.clientTop, element.clientWidth, element.clientHeight);
}

function textColumn(element: HTMLElement): { left: number; width: number } {
  const style = getComputedStyle(element);
  const rect = element.getBoundingClientRect();
  const paddingLeft = parseFloat(style.paddingLeft) || 0;
  const paddingRight = parseFloat(style.paddingRight) || 0;
  return { left: rect.left + element.clientLeft + paddingLeft, width: element.clientWidth - paddingLeft - paddingRight };
}

/** Ghost text for the rich-text editor, through its plugin hook. */
export function ghostTextPlugin(api: Api, subject: () => string): EditorPlugin {
  return (editor: Squire, root: HTMLElement) => {
    const container = root.parentElement!;
    const assistant = createAssistant(api, subject, {
      container,
      focused: () => root.contains(document.activeElement),
      context: () => {
        const range = editor.getSelection();
        if (!range.collapsed || !root.contains(range.startContainer)) return null;
        const at = range.startContainer.nodeType === Node.ELEMENT_NODE ? range.startContainer as Element : range.startContainer.parentElement;
        if (at?.closest(NOT_DRAFT)) return null;
        const before = document.createRange();
        before.setStart(root, 0);
        before.setEnd(range.startContainer, range.startOffset);
        const after = document.createRange();
        after.setStart(range.startContainer, range.startOffset);
        after.setEnd(root, root.childNodes.length);
        const quoted = Array.from(root.querySelectorAll('blockquote[type="cite"]')).map((quote) => contentText(quote)).join('\n');
        return { before: contentText(before.cloneContents(), NOT_DRAFT), after: contentText(after.cloneContents(), NOT_DRAFT), quoted };
      },
      caretBox: () => {
        const range = editor.getSelection();
        if (!range.collapsed) return null;
        const caret = editor.getCursorPosition();
        if (!caret || (!caret.top && !caret.left)) return null;
        const at = range.startContainer.nodeType === Node.ELEMENT_NODE ? range.startContainer as Element : range.startContainer.parentElement;
        return { caret, ...textColumn(root), styleFrom: at || root, clip: visibleRect(root) };
      },
      insert: (text) => {
        // Squire trims a leading space off inserted text; a non-breaking one
        // keeps the words apart, as browsers do for a typed trailing space.
        editor.insertPlainText(text.replace(/^ /, '\u00A0'), false);
        editor.focus();
      },
    });
    // Tab accepts through Squire's key handlers; otherwise Tab keeps its
    // usual meaning (indenting list items).
    const tab = editor._keyHandlers.Tab;
    editor.setKeyHandler('Tab', (self, event, range) => {
      if (!assistant.accept()) tab?.(self, event, range);
      else event.preventDefault();
    });
    // Squire's own key handling runs first (it was attached earlier); Esc
    // must also stop the compose window from closing.
    const onKey = (event: KeyboardEvent) => { if (event.key !== 'Tab') assistant.keydown(event); };
    const onInput = () => assistant.changed();
    const dismiss = () => assistant.dismiss();
    root.addEventListener('keydown', onKey);
    // The browser's input event, not Squire's: Squire also fires its own for
    // every DOM change it makes itself (a MutationObserver), such as the
    // marker getCursorPosition() inserts, which would dismiss the ghost as
    // soon as it is drawn.
    root.addEventListener('input', onInput);
    editor.addEventListener('blur', dismiss);
    root.addEventListener('scroll', dismiss);
    root.addEventListener('mousedown', dismiss);
    return () => {
      editor.setKeyHandler('Tab', tab ?? null);
      root.removeEventListener('keydown', onKey);
      root.removeEventListener('input', onInput);
      editor.removeEventListener('blur', dismiss);
      root.removeEventListener('scroll', dismiss);
      root.removeEventListener('mousedown', dismiss);
      assistant.destroy();
    };
  };
}

/** Styles that decide where text in a textarea wraps, copied to measure the caret. */
const MIRRORED = [
  'boxSizing', 'width', 'borderTopWidth', 'borderRightWidth', 'borderBottomWidth', 'borderLeftWidth',
  'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft', 'fontStyle', 'fontVariant', 'fontWeight',
  'fontStretch', 'fontSize', 'lineHeight', 'fontFamily', 'textAlign', 'textTransform', 'textIndent',
  'letterSpacing', 'wordSpacing', 'tabSize',
] as const;

/** Viewport position of the caret at `position` in a textarea, measured with a hidden copy. */
function textareaCaret(textarea: HTMLTextAreaElement, position: number): DOMRect {
  const style = getComputedStyle(textarea);
  const mirror = document.createElement('div');
  for (const name of MIRRORED) mirror.style[name] = style[name];
  Object.assign(mirror.style, { position: 'absolute', visibility: 'hidden', whiteSpace: 'pre-wrap', overflowWrap: 'break-word', top: '0', left: '-9999px', overflow: 'hidden' });
  mirror.textContent = textarea.value.slice(0, position);
  const marker = document.createElement('span');
  marker.textContent = '​';
  mirror.appendChild(marker);
  document.body.appendChild(mirror);
  const rect = textarea.getBoundingClientRect();
  const left = rect.left + marker.offsetLeft - textarea.scrollLeft;
  const top = rect.top + marker.offsetTop - textarea.scrollTop;
  const height = marker.offsetHeight;
  mirror.remove();
  return new DOMRect(left, top, 0, height);
}

/** Insert into a textarea so the browser's own undo can take it back. */
export function insertIntoTextarea(textarea: HTMLTextAreaElement, text: string, start: number, end: number) {
  textarea.focus();
  textarea.setSelectionRange(start, end);
  if (!document.execCommand('insertText', false, text)) {
    textarea.setRangeText(text, start, end, 'end');
    textarea.dispatchEvent(new Event('input', { bubbles: true }));
  }
}

/** Ghost text for the plain-text editor; returns its cleanup. */
export function attachTextareaGhost(api: Api, subject: () => string, textarea: HTMLTextAreaElement): () => void {
  const container = textarea.parentElement!;
  const assistant = createAssistant(api, subject, {
    container,
    focused: () => document.activeElement === textarea,
    context: () => {
      if (textarea.selectionStart !== textarea.selectionEnd) return null;
      const position = textarea.selectionStart;
      const value = textarea.value;
      const head = splitPlain(value.slice(0, position));
      const whole = splitPlain(value);
      // A caret inside a quoted line or the signature gets nothing.
      const line = value.slice(value.lastIndexOf('\n', position - 1) + 1, position);
      if (line.startsWith('>') || value.slice(0, position).split('\n').includes('-- ')) return null;
      return { before: head.draft, after: splitPlain(value.slice(position)).draft, quoted: whole.quoted };
    },
    caretBox: () => {
      if (textarea.selectionStart !== textarea.selectionEnd) return null;
      return { caret: textareaCaret(textarea, textarea.selectionStart), ...textColumn(textarea), styleFrom: textarea, clip: visibleRect(textarea) };
    },
    insert: (text) => {
      const at = textarea.selectionStart;
      insertIntoTextarea(textarea, text, at, at);
    },
  });
  const onKey = (event: KeyboardEvent) => assistant.keydown(event);
  const onInput = () => assistant.changed();
  const dismiss = () => assistant.dismiss();
  textarea.addEventListener('keydown', onKey);
  textarea.addEventListener('input', onInput);
  textarea.addEventListener('blur', dismiss);
  textarea.addEventListener('scroll', dismiss);
  textarea.addEventListener('mousedown', dismiss);
  return () => {
    textarea.removeEventListener('keydown', onKey);
    textarea.removeEventListener('input', onInput);
    textarea.removeEventListener('blur', dismiss);
    textarea.removeEventListener('scroll', dismiss);
    textarea.removeEventListener('mousedown', dismiss);
    assistant.destroy();
  };
}
