el.innerHTML = null;
el.outerHTML = (null);
el.innerHTML = (null as string | null);
export function Reset() { return <div dangerouslySetInnerHTML={{ __html: null }} />; }
export function nullable(html: string | null) { el.innerHTML = html; }
export function fallback(html) { el.innerHTML = html ?? null; }
export function orFallback(html) { el.innerHTML = html || null; }
export function assertion(html) { el.innerHTML = html as null; }
export function Dynamic({ html }) { return <div dangerouslySetInnerHTML={{ __html: html ?? null }} />; }
document.write(null, untrusted);
el.innerHTML += null;
