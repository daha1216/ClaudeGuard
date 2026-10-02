// 内联 SVG 图标库 — v1 教训: 禁止字体字形/emoji(豆腐块), 全部矢量。
// 普通脚本加载, 暴露全局 ICONS; 颜色走 currentColor(由父元素 color 控制)。
window.ICONS = {
  minimize: '<svg viewBox="0 0 10 10" aria-hidden="true"><rect x="0" y="4.5" width="10" height="1" fill="currentColor"/></svg>',
  maximize: '<svg viewBox="0 0 10 10" aria-hidden="true"><rect x="0.5" y="0.5" width="9" height="9" fill="none" stroke="currentColor" stroke-width="1"/></svg>',
  restore: '<svg viewBox="0 0 10 10" aria-hidden="true"><rect x="0.5" y="2.5" width="7" height="7" fill="none" stroke="currentColor" stroke-width="1"/><path d="M2.5 2.5 V0.5 h7 v7 H7.5" fill="none" stroke="currentColor" stroke-width="1"/></svg>',
  close: '<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M0.5 0.5 L9.5 9.5 M9.5 0.5 L0.5 9.5" fill="none" stroke="currentColor" stroke-width="1"/></svg>',
  chevron: '<svg viewBox="0 0 12 12" aria-hidden="true"><path d="M3.5 1.5 L8 6 L3.5 10.5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  warning: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5 L15 14.5 H1 Z" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><rect x="7.4" y="6" width="1.2" height="4.2" fill="currentColor"/><rect x="7.4" y="11.4" width="1.2" height="1.2" fill="currentColor"/></svg>',
  install: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 3v8.2m0 0 3.4-3.4M10 11.2 6.6 7.8" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 15.8h12" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
  portable: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M12 2 6 11h4l-1 7 6-9h-4z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>',
};
