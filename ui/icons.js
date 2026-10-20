/* ClaudeGuard v3 — 内联图标（24×24 viewBox，currentColor 描边）。
   契约：window.ICONS = { name: svgString }。 */
(() => {
  "use strict";

  const root = typeof window !== "undefined" ? window : globalThis;

  const s = (body, width) => '<svg viewBox="0 0 24 24" width="' + (width || 20) + '" height="' + (width || 20) +
    '" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + body + '</svg>';

  const ICONS = {
    check: s('<path d="M4.5 12.5l4.6 4.6L19.5 6.7"/>', 22),
    x: s('<path d="M6 6l12 12M18 6L6 18"/>', 22),
    alert: s('<path d="M12 3.6L21.2 20H2.8L12 3.6z"/><path d="M12 9.6v4.2"/><path d="M12 17.2h.01"/>'),
    info: s('<circle cx="12" cy="12" r="8.6"/><path d="M12 11v5.4"/><path d="M12 7.8h.01"/>'),
    dash: s('<path d="M6 12h12"/>', 22),
    play: s('<path d="M8 5.4l11 6.6-11 6.6z" fill="currentColor" stroke="none"/>', 16),
    stop: s('<rect x="6.5" y="6.5" width="11" height="11" rx="2.4" fill="currentColor" stroke="none"/>', 16),
    ban: s('<circle cx="12" cy="12" r="8.4"/><path d="M6.1 17.9L17.9 6.1"/>', 16),
    pause: s('<path d="M8.5 5.5v13M15.5 5.5v13"/>', 16),
    rotate: s('<path d="M20.5 12a8.5 8.5 0 1 1-2.5-6"/><path d="M20.5 4.2v4.3h-4.3"/>', 20),
    refreshCw: s('<path d="M20.5 12a8.5 8.5 0 1 1-2.5-6"/><path d="M20.5 4.2v4.3h-4.3"/>', 16),
    refresh: s('<path d="M20.5 12a8.5 8.5 0 1 1-2.5-6"/><path d="M20.5 4.2v4.3h-4.3"/>', 16),
    unlock: s('<rect x="4.2" y="10.6" width="15.6" height="9.8" rx="2.6"/><path d="M8.2 10.6V7.5a3.8 3.8 0 0 1 7.3-1.6"/>', 16),
    link: s('<path d="M10.2 13.8a3.6 3.6 0 0 0 5.1 0l3-3a3.6 3.6 0 1 0-5.1-5.1l-1.4 1.4"/><path d="M13.8 10.2a3.6 3.6 0 0 0-5.1 0l-3 3a3.6 3.6 0 1 0 5.1 5.1l1.4-1.4"/>', 14),
    gear: s('<circle cx="12" cy="12" r="3.1"/><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1z"/>', 14),
    fileText: s('<path d="M13.6 3.4H7.4A2 2 0 0 0 5.4 5.4v13.2a2 2 0 0 0 2 2h9.2a2 2 0 0 0 2-2V8.6z"/><path d="M13.4 3.6v5h5"/><path d="M9 13h6M9 16.4h4"/>', 14),
    trash: s('<path d="M4.6 7h14.8"/><path d="M9.4 7V5.6a1.6 1.6 0 0 1 1.6-1.6h2a1.6 1.6 0 0 1 1.6 1.6V7"/><path d="M6.6 7l.8 11.2a2 2 0 0 0 2 1.8h5.2a2 2 0 0 0 2-1.8L17.4 7"/>', 14),
    plus: s('<path d="M12 5.5v13M5.5 12h13"/>', 14),
    chevronDown: s('<path d="M5.5 8.8l6.5 6.4 6.5-6.4"/>', 12),
    download: s('<path d="M12 4.5v10.4"/><path d="M7.8 11l4.2 4.2 4.2-4.2"/><path d="M4.5 19.5h15"/>', 16),
    copy: s('<rect x="9.2" y="9.2" width="10.4" height="10.4" rx="2.2"/><path d="M6.8 14.8H5.6a2 2 0 0 1-2-2V5.6a2 2 0 0 1 2-2h7.2a2 2 0 0 1 2 2v1.2"/>', 16),
    external: s('<path d="M14 4.5h5.5V10"/><path d="M19.5 4.5L11 13"/><path d="M17.5 13.6v4.4a2 2 0 0 1-2 2H5.6a2 2 0 0 1-2-2V7.6a2 2 0 0 1 2-2h4.4"/>', 14),
    send: s('<path d="M21 3.6L10.6 14"/><path d="M21 3.6l-6.3 17-4.1-6.6-6.6-4.1z"/>', 16),
    bell: s('<path d="M18 8.6a6 6 0 1 0-12 0c0 6-2.2 7.4-2.2 7.4h16.4S18 14.6 18 8.6z"/><path d="M13.7 19.6a2.1 2.1 0 0 1-3.4 0"/>', 14),
    shield: s('<path d="M12 3l7.4 2.8v5.4c0 4.6-3.1 7.9-7.4 9.6-4.3-1.7-7.4-5-7.4-9.6V5.8z"/>', 14),
    clock: s('<circle cx="12" cy="12" r="8.6"/><path d="M12 7.4V12l3 1.8"/>', 14),
    folder: s('<path d="M4 7.4a2 2 0 0 1 2-2h4l2 2.4h6a2 2 0 0 1 2 2v7.8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/>', 14),
    checkCircle: s('<circle cx="12" cy="12" r="8.6"/><path d="M8.2 12.4l2.6 2.6 5.2-5.6"/>', 14),
    alertCircle: s('<circle cx="12" cy="12" r="8.6"/><path d="M12 7.8v5"/><path d="M12 16.2h.01"/>', 14)
  };

  root.ICONS = ICONS;
})();
