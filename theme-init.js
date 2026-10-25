// Setzt Modus und Sprache vor dem ersten Zeichnen (eigene Datei statt Inline-Skript wegen der CSP).
(function () {
	var root = document.documentElement;
	var theme = null;
	var lang = null;
	try {
		theme = localStorage.getItem('tl-theme');
		lang = localStorage.getItem('tl-lang');
	} catch (e) {
		// Speicher gesperrt: Systemeinstellung und Browsersprache
	}
	if (theme !== 'light' && theme !== 'dark') {
		try {
			theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
		} catch (e) {
			theme = 'light';
		}
	}
	if (lang !== 'de' && lang !== 'en') {
		lang = String(navigator.language || '').toLowerCase().indexOf('de') === 0 ? 'de' : 'en';
	}
	root.dataset.theme = theme;
	root.lang = lang;
})();
