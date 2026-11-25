(() => {
 // Themes: graphite (default, neutral black + brand blue), midnight (the old
 // navy + cyan) and light. The choice persists in localStorage.
 const THEMES = ['graphite', 'midnight', 'light'];
 function apply(theme) {
 if (theme === 'light' || theme === 'midnight') document.documentElement.setAttribute('data-theme', theme);
 else document.documentElement.removeAttribute('data-theme'); // graphite default
 const btn = document.getElementById('theme-toggle-btn');
 if (btn) btn.textContent = theme.charAt(0).toUpperCase() + theme.slice(1);
 }
 function current() {
 const v = document.documentElement.getAttribute('data-theme');
 return v === 'light' || v === 'midnight' ? v : 'graphite';
 }
 window.toggleTheme = () => {
 const next = THEMES[(THEMES.indexOf(current()) + 1) % THEMES.length];
 try { localStorage.setItem('autoar_theme', next); } catch (e) { /* ignore */ }
 // Suppress every transition for the flip: without this all color
 // transitions fire at once and the switch smears. The override resolves
 // the new theme, flushes styles, then leaves after the next paint.
 const guard = document.createElement('style');
 guard.append(document.createTextNode('*,*::before,*::after{transition:none !important}'));
 document.head.append(guard);
 apply(next);
 void document.body.offsetHeight; // force a synchronous style flush
 requestAnimationFrame(() => { requestAnimationFrame(() => guard.remove()); });
 };
 let saved = 'graphite';
 try { saved = localStorage.getItem('autoar_theme') || 'graphite'; } catch (e) { /* ignore */ }
 apply(saved);
})();
