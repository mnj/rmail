// The rich-text editor used to write messages and signatures: Squire (a small
// contenteditable editor made for email) with a toolbar, paste cleanup through
// DOMPurify and inline images. Native spellchecking stays on: the editable
// root carries `spellcheck` and the `lang` of the user's compose language.
//
// The server cleans the HTML again before it is sent or stored
// (rmail_common::compose_html); the cleanup here keeps the editor's own
// document safe and pastes from Word or Google Docs tidy.

import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react';
import DOMPurify from 'dompurify';
import Squire from 'squire-rte';
import {
  Bold, Eraser, Image as ImageIcon, IndentDecrease, Italic, Link2, List, ListOrdered, Quote, Redo2, Strikethrough, Underline, Undo2, Unlink,
} from 'lucide-react';

/**
 * Something layered over the editor, attached once the editor exists; returns
 * its cleanup. Suggestions shown as ghost text (a later feature) plug in here:
 * a plugin listens to `input`/`pathChange` on `editor`, reads the text before
 * the caret from `editor.getSelection()`, draws the suggestion in an overlay
 * positioned with `editor.getCursorPosition()` (never inside the document, so
 * getHTML() and undo stay clean) and inserts it with `editor.insertPlainText`
 * when accepted (Tab), via `editor.setKeyHandler('Tab', ...)`.
 */
export type EditorPlugin = (editor: Squire, root: HTMLElement) => (() => void) | void;

export type EditorHandle = {
  getHTML: () => string;
  setHTML: (html: string) => void;
  /** Plain text of the content, as the user sees it. */
  getText: () => string;
  insertHTML: (html: string) => void;
  insertImages: (files: File[]) => Promise<void>;
  focus: (where?: 'start' | 'end') => void;
};

type Props = {
  initialHtml: string;
  lang?: string;
  label: string;
  onChange?: () => void;
  /** Ctrl/Cmd+Enter. */
  onSubmit?: () => void;
  /** Files dropped on the editor that are not images (attachments). */
  onFiles?: (files: File[]) => void;
  plugins?: EditorPlugin[];
  /** A smaller editor without image and quote buttons (signatures). */
  compact?: boolean;
  className?: string;
};

/** Style properties kept from pasted HTML; the rest (mso-*, positions, fonts of the source page) goes. */
const PASTE_STYLES = new Set([
  'color', 'background-color', 'font-weight', 'font-style', 'text-decoration', 'text-align', 'font-size',
  'vertical-align', 'border', 'border-collapse', 'padding', 'width',
]);
/** Classes Squire uses for its own formatting spans. */
const SQUIRE_CLASSES = new Set(['size', 'color', 'font', 'highlight']);

let hooksInstalled = false;

function installHooks() {
  if (hooksInstalled) return;
  hooksInstalled = true;
  DOMPurify.addHook('uponSanitizeAttribute', (_node, data) => {
    if (data.attrName === 'class') {
      data.attrValue = data.attrValue.split(/\s+/).filter((name) => SQUIRE_CLASSES.has(name)).join(' ');
      if (!data.attrValue) data.keepAttr = false;
    } else if (data.attrName === 'style') {
      const kept = data.attrValue.split(';').map((rule) => rule.trim()).filter((rule) => {
        const [property, ...rest] = rule.split(':');
        const value = rest.join(':').toLowerCase();
        return PASTE_STYLES.has(property.trim().toLowerCase()) && value && !value.includes('url(') && !value.includes('expression');
      });
      if (kept.length) data.attrValue = kept.join('; ');
      else data.keepAttr = false;
    }
  });
}

function sanitize(html: string): DocumentFragment {
  installHooks();
  const fragment = DOMPurify.sanitize(html, {
    RETURN_DOM_FRAGMENT: true,
    FORBID_TAGS: ['style', 'form', 'input', 'button', 'textarea', 'select', 'option', 'svg', 'math', 'iframe', 'object', 'embed', 'audio', 'video', 'meta', 'link', 'base', 'title'],
    FORBID_ATTR: ['id', 'name', 'contenteditable', 'srcset', 'background'],
  });
  return document.importNode(fragment, true);
}

function readAsDataUrl(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(blob);
  });
}

/** Largest side of an inline image; bigger photos are scaled down before they go into the message. */
const MAX_IMAGE_SIDE = 1600;

/** The image as a data URL, scaled down when it is large. */
async function imageDataUrl(file: File): Promise<string> {
  const original = await readAsDataUrl(file);
  if (file.type === 'image/gif' || file.size < 300 * 1024) return original;
  try {
    const image = new Image();
    image.src = original;
    await image.decode();
    const scale = Math.min(1, MAX_IMAGE_SIDE / Math.max(image.naturalWidth, image.naturalHeight));
    if (scale === 1 && file.size < 1024 * 1024) return original;
    const canvas = document.createElement('canvas');
    canvas.width = Math.round(image.naturalWidth * scale);
    canvas.height = Math.round(image.naturalHeight * scale);
    canvas.getContext('2d')?.drawImage(image, 0, 0, canvas.width, canvas.height);
    const scaled = canvas.toDataURL(file.type === 'image/png' ? 'image/png' : 'image/jpeg', 0.85);
    return scaled.length < original.length ? scaled : original;
  } catch {
    return original;
  }
}

const isImage = (file: File) => ['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(file.type);

const SIZES: [string, string][] = [['', 'Normal'], ['12px', 'Small'], ['18px', 'Large'], ['24px', 'Huge']];

export const RichEditor = forwardRef<EditorHandle, Props>(function RichEditor(
  { initialHtml, lang, label, onChange, onSubmit, onFiles, plugins, compact, className },
  ref,
) {
  const rootRef = useRef<HTMLDivElement>(null);
  const editorRef = useRef<Squire | null>(null);
  const imageInput = useRef<HTMLInputElement>(null);
  const [path, setPath] = useState('');
  const [undo, setUndo] = useState({ canUndo: false, canRedo: false });
  const [linking, setLinking] = useState<string | null>(null);
  // Callbacks change on every render; the editor's listeners read the latest.
  const latest = useRef({ onChange, onSubmit, onFiles });
  latest.current = { onChange, onSubmit, onFiles };

  async function insertImages(files: File[]) {
    const editor = editorRef.current;
    if (!editor) return;
    for (const file of files.filter(isImage)) {
      editor.insertImage(await imageDataUrl(file), { alt: file.name.replace(/\.[^.]+$/, '') });
    }
    latest.current.onChange?.();
  }

  useEffect(() => {
    const root = rootRef.current!;
    const editor = new Squire(root, {
      blockTag: 'DIV',
      sanitizeToDOMFragment: (html: string) => sanitize(html),
      didError: (error: unknown) => console.warn('editor', error),
    });
    editorRef.current = editor;
    editor.setHTML(initialHtml || '');
    const changed = () => latest.current.onChange?.();
    const onPath = () => setPath(editor.getPath());
    const onUndo = (event: Event) => setUndo((event as CustomEvent).detail);
    const onPasteImage = (event: Event) => {
      const data = (event as CustomEvent<{ clipboardData: DataTransfer }>).detail.clipboardData;
      insertImages(Array.from(data.files));
    };
    editor.addEventListener('input', changed);
    editor.addEventListener('pathChange', onPath);
    editor.addEventListener('undoStateChange', onUndo);
    editor.addEventListener('pasteImage', onPasteImage);
    const submit = (_: Squire, event: KeyboardEvent) => { event.preventDefault(); latest.current.onSubmit?.(); };
    editor.setKeyHandler('Ctrl-Enter', submit);
    editor.setKeyHandler('Meta-Enter', submit);
    // Dropped files: images go into the text, anything else is attached.
    const onDrop = (event: DragEvent) => {
      const files = Array.from(event.dataTransfer?.files || []);
      if (!files.length) return;
      event.preventDefault();
      event.stopPropagation();
      insertImages(files);
      const others = files.filter((file) => !isImage(file));
      if (others.length) latest.current.onFiles?.(others);
    };
    root.addEventListener('drop', onDrop);
    const cleanups = (plugins || []).map((plugin) => plugin(editor, root));
    return () => {
      cleanups.forEach((cleanup) => cleanup?.());
      root.removeEventListener('drop', onDrop);
      editor.destroy();
      editorRef.current = null;
    };
    // The editor is created once; later prop changes go through the handle.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useImperativeHandle(ref, () => ({
    getHTML: () => editorRef.current?.getHTML() ?? '',
    setHTML: (html) => editorRef.current?.setHTML(html),
    getText: () => rootRef.current?.innerText ?? '',
    insertHTML: (html) => editorRef.current?.insertHTML(html),
    insertImages,
    focus: (where) => {
      const editor = editorRef.current;
      if (!editor) return;
      editor.focus();
      if (where === 'start') editor.moveCursorToStart();
      if (where === 'end') editor.moveCursorToEnd();
    },
  }));

  const editor = editorRef.current;
  const has = (tag: string) => new RegExp(`(^|>)${tag}\\b`).test(path);
  const run = (action: (e: Squire) => void) => () => {
    if (!editorRef.current) return;
    action(editorRef.current);
    editorRef.current.focus();
    latest.current.onChange?.();
  };
  const toggle = (tag: string, on: (e: Squire) => void, off: (e: Squire) => void) => run((e) => (has(tag) ? off(e) : on(e)));

  function applyLink() {
    let url = (linking || '').trim();
    if (url && !/^(https?:|mailto:|tel:)/i.test(url)) url = url.includes('@') && !url.includes('/') ? `mailto:${url}` : `https://${url}`;
    if (url) run((e) => e.makeLink(url))();
    setLinking(null);
  }

  const button = (title: string, Icon: React.ElementType, onClick: () => void, active = false, disabled = false) => (
    <button type="button" className={`tool ${active ? 'active' : ''}`} title={title} aria-label={title} aria-pressed={active || undefined} disabled={disabled} onMouseDown={(e) => e.preventDefault()} onClick={onClick}>
      <Icon size={15} />
    </button>
  );
  const mod = /Mac|iP(hone|ad)/.test(navigator.platform) ? '⌘' : 'Ctrl+';
  const currentSize = editor && path ? editor.getFontInfo().fontSize || '' : '';

  return (
    <div className={`rich-editor ${compact ? 'compact' : ''} ${className || ''}`}>
      <div className="editor-toolbar" role="toolbar" aria-label="Formatting">
        {linking === null ? <>
          {button(`Bold (${mod}B)`, Bold, toggle('B', (e) => e.bold(), (e) => e.removeBold()), has('B'))}
          {button(`Italic (${mod}I)`, Italic, toggle('I', (e) => e.italic(), (e) => e.removeItalic()), has('I'))}
          {button(`Underline (${mod}U)`, Underline, toggle('U', (e) => e.underline(), (e) => e.removeUnderline()), has('U'))}
          {!compact && button('Strikethrough', Strikethrough, toggle('S', (e) => e.strikethrough(), (e) => e.removeStrikethrough()), has('S'))}
          <select className="tool-select" aria-label="Text size" title="Text size" value={SIZES.some(([v]) => v === currentSize) ? currentSize : ''} onChange={(e) => run((ed) => ed.setFontSize(e.target.value || null))()}>
            {SIZES.map(([value, name]) => <option key={name} value={value}>{name}</option>)}
          </select>
          <span className="tool-divider" />
          {button('Bulleted list', List, toggle('UL', (e) => e.makeUnorderedList(), (e) => e.removeList()), has('UL'))}
          {button('Numbered list', ListOrdered, toggle('OL', (e) => e.makeOrderedList(), (e) => e.removeList()), has('OL'))}
          {!compact && button('Quote', Quote, run((e) => e.increaseQuoteLevel()), has('BLOCKQUOTE'))}
          {!compact && has('BLOCKQUOTE') && button('Remove quote level', IndentDecrease, run((e) => e.decreaseQuoteLevel()))}
          <span className="tool-divider" />
          {has('A') ? button('Remove link', Unlink, run((e) => e.removeLink()), true) : button(`Link (${mod}K)`, Link2, () => setLinking(''))}
          {button('Insert image', ImageIcon, () => imageInput.current?.click())}
          {button('Clear formatting', Eraser, run((e) => e.removeAllFormatting()))}
          <span className="tool-spacer" />
          {button(`Undo (${mod}Z)`, Undo2, run((e) => e.undo()), false, !undo.canUndo)}
          {button('Redo', Redo2, run((e) => e.redo()), false, !undo.canRedo)}
        </> : (
          <div className="link-form">
            <Link2 size={15} />
            <input autoFocus aria-label="Link address" placeholder="https://example.com or name@example.com" value={linking} onChange={(e) => setLinking(e.target.value)} onKeyDown={(e) => {
              if (e.key === 'Enter') { e.preventDefault(); applyLink(); }
              if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); setLinking(null); }
            }} />
            <button className="secondary small-button" type="button" onClick={applyLink}>Apply</button>
            <button className="link" type="button" onClick={() => setLinking(null)}>Cancel</button>
          </div>
        )}
        <input ref={imageInput} type="file" accept="image/png,image/jpeg,image/gif,image/webp" multiple hidden onChange={(e) => { insertImages(Array.from(e.target.files || [])); e.target.value = ''; }} />
      </div>
      <div
        ref={rootRef}
        className="editor-root"
        role="textbox"
        aria-multiline="true"
        aria-label={label}
        spellCheck
        lang={lang || undefined}
        onKeyDown={(e) => {
          if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setLinking(''); }
        }}
      />
    </div>
  );
});

/** Escape text for HTML. */
export function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** Plain text as editor HTML: one block per line, links left as typed. */
export function textToHtml(text: string): string {
  return text.split('\n').map((line) => `<div>${line ? escapeHtml(line) : '<br>'}</div>`).join('');
}
