/* segreto.js — cifratura/decifratura dei contenuti con il codice come password.
   Non modificare. Usa solo Web Crypto del browser (nessuna libreria esterna).
   Formato: base64( sale 16 byte + iv 12 byte + testo cifrato ).
   Chiave: PBKDF2 (SHA-256, 200000 giri) dal codice -> AES-GCM 256.
   Con il codice sbagliato la decifratura fallisce (AES-GCM controlla l'integrità). */
globalThis.SEGRETO = (() => {
  const enc = new TextEncoder(), dec = new TextDecoder();
  const GIRI = 200000;

  const normalizza = c => String(c).toLowerCase().replace(/[^a-z]/g, '');

  const inB64 = u8 => {
    let s = '';
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const daB64 = s => Uint8Array.from(atob(s), ch => ch.charCodeAt(0));

  async function chiave(codice, sale) {
    const base = await crypto.subtle.importKey('raw', enc.encode(normalizza(codice)), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: sale, iterations: GIRI, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  async function cifra(testo, codice) {
    const sale = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const k = await chiave(codice, sale);
    const dati = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, enc.encode(testo)));
    const out = new Uint8Array(28 + dati.length);
    out.set(sale, 0); out.set(iv, 16); out.set(dati, 28);
    return inB64(out);
  }

  // Restituisce il testo, oppure null se il codice è sbagliato o i dati sono rovinati.
  async function decifra(blob, codice) {
    try {
      const b = daB64(blob);
      const k = await chiave(codice, b.slice(0, 16));
      return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(16, 28) }, k, b.slice(28)));
    } catch (e) { return null; }
  }

  // Controllo del codice per index.html: decifra un piccolo blocco di prova.
  async function verificaCodice(codice) {
    return (await decifra(globalThis.DATI.check, codice)) === 'ok';
  }

  return { cifra, decifra, verificaCodice, normalizza };
})();
