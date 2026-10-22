// IoTShield opening screen: the keyhole draws itself while hex digits drift behind it, a short
// HMAC handshake is typed underneath, the lock clicks shut, then we fly through the keyhole.
(() => {
  'use strict';

  const splash = document.getElementById('splash');
  const door = document.getElementById('door');
  const term = document.getElementById('term');
  const canvas = document.getElementById('rain');
  const context = canvas.getContext('2d');
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const DRAW_MS = 1500;          // the keyhole traces itself first
  const LINE_GAP_MS = 380;       // pause between handshake lines
  const HOLD_MS = 1500;          // time to read the name before flying in
  const FLY_MS = 1000;           // zoom through the keyhole (matches splash.css)
  const FADE_MS = 350;

  /* ---------- hex digits drifting in the dark, brighter near the keyhole ---------- */
  const SIZE = 15;
  const HEX = '0123456789abcdef';
  let width = 0, height = 0, drops = [];
  const light = { x: 0, y: 0 };

  function resize() {
    const ratio = window.devicePixelRatio || 1;
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.fillStyle = '#060503';
    context.fillRect(0, 0, width, height);
    context.font = `${SIZE - 2}px "JetBrains Mono", ui-monospace, Menlo, monospace`;
    drops = Array.from({ length: Math.ceil(width / SIZE) }, () => ({ y: Math.random() * height, skip: Math.random() }));
    const box = door.getBoundingClientRect();           // the ring's centre is where the "light" comes from
    light.x = box.left + box.width * 0.501;
    light.y = box.top + box.height * 0.244;
  }

  let last = 0;
  function rain(now) {
    requestAnimationFrame(rain);
    if (now - last < 75) return;                        // ~13 steps a second reads as falling code, not a smear
    last = now;
    context.fillStyle = 'rgba(6, 5, 3, 0.16)';          // fades older digits into trails
    context.fillRect(0, 0, width, height);
    const reach = 0.62 * Math.min(width, height);
    drops.forEach((drop, column) => {
      if (drop.skip > 0.62) { drop.skip = Math.random(); return; }   // some columns rest each step
      const x = column * SIZE;
      const near = Math.max(0, 1 - Math.hypot(x - light.x, drop.y - light.y) / reach);
      context.fillStyle = `rgba(243, 198, 63, ${0.06 + 0.5 * near * near})`;
      context.fillText(HEX[(Math.random() * 16) | 0], x, drop.y);
      drop.y = drop.y > height + SIZE && Math.random() > 0.96 ? 0 : drop.y + SIZE;
      drop.skip = Math.random();
    });
  }

  resize();
  window.addEventListener('resize', resize);
  if (!reducedMotion) requestAnimationFrame(rain);

  /* ---------- a real HMAC-SHA256 handshake (throw-away key, computed here in the browser) ---------- */
  const randomBytes = (length) => crypto.getRandomValues(new Uint8Array(length));
  const toHex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  const short = (hex) => `${hex.slice(0, 12)}…${hex.slice(-4)}`;

  async function handshake() {
    const challenge = randomBytes(32);
    const key = randomBytes(32);
    let mac;
    try {
      const imported = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      mac = new Uint8Array(await crypto.subtle.sign('HMAC', imported, challenge));
    } catch (error) {
      mac = randomBytes(32);                            // WebCrypto unavailable (plain-http, old browser): decorative only
    }
    return { challenge: toHex(challenge), mac: toHex(mac) };
  }

  async function typeInto(row, text, delay = 16) {
    const value = row.querySelector('.v');
    row.classList.add('on');
    value.classList.add('typing');
    for (let i = 1; i <= text.length && !entering; i++) {
      value.textContent = text.slice(0, i);
      await sleep(delay);
    }
    value.classList.remove('typing');
  }

  /* ---------- the sequence ---------- */
  let entering = false;

  function enter() {                                    // fly through the keyhole, then on to the app
    if (entering) return;
    entering = true;
    splash.classList.add('entering');
    setTimeout(() => splash.classList.add('leaving'), reducedMotion ? 0 : FLY_MS - 200);
    setTimeout(() => { window.location.href = '/home'; }, (reducedMotion ? 0 : FLY_MS - 200) + FADE_MS);
  }

  async function run() {
    const pending = handshake();
    await sleep(reducedMotion ? 300 : DRAW_MS);
    if (entering) return;
    const rows = Object.fromEntries([...term.querySelectorAll('.row')].map((row) => [row.dataset.row, row]));
    const { challenge, mac } = await pending;

    await typeInto(rows.challenge, short(challenge));
    await sleep(LINE_GAP_MS);
    await typeInto(rows.hmac, short(mac));
    await sleep(LINE_GAP_MS);
    await typeInto(rows.verdict, 'ACCESS GRANTED', 30);
    await sleep(450);
    if (entering) return;

    splash.classList.add('unlocked');                   // bolt drops into the slot, the name rises
    await sleep(HOLD_MS);
    enter();
  }

  document.addEventListener('click', enter);            // click or press any key to skip
  document.addEventListener('keydown', enter);
  run();
})();
