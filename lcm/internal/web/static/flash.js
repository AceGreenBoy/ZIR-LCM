// USB flashing of the bootstrap from the browser (Web Serial + esptool-js).
// The only script of the admin UI: the page works as plain HTML otherwise.
// It writes flash and nothing else: no eFuse commands (L0, CLAUDE.md).
import { ESPLoader, Transport } from "./esptool/esptool.js";

const MIN_CHIP_REV = 3; // bootstrap is built with CONFIG_ESP32_REV_MIN_3

const $ = (id) => document.getElementById(id);
const root = $("flash");
const csrf = root.dataset.csrf || "";
const imagePrefix = root.dataset.image; // "/builds/" (admin) or "/bootstrap/" (public)
const doneURL = root.dataset.done;

const ui = {
  build: $("fl-build"),
  baud: $("fl-baud"),
  erase: $("fl-erase"),
  connect: $("fl-connect"),
  flash: $("fl-flash"),
  disconnect: $("fl-disconnect"),
  chip: $("fl-chip"),
  progress: $("fl-progress"),
  status: $("fl-status"),
  log: $("fl-log"),
  done: $("fl-done"),
};

let transport = null;
let loader = null;
let chipInfo = null;
let busy = false;

function log(line) {
  ui.log.textContent += line + "\n";
  ui.log.scrollTop = ui.log.scrollHeight;
}

function status(text, cls) {
  ui.status.textContent = text;
  ui.status.className = "flash " + (cls || "");
  ui.status.hidden = !text;
}

function sync() {
  const connected = loader !== null;
  ui.connect.disabled = busy || connected;
  ui.disconnect.disabled = busy || !connected;
  ui.flash.disabled = busy || !connected || !chipInfo || !chipInfo.ok || !ui.build.value;
  ui.build.disabled = busy;
  ui.baud.disabled = busy || connected;
  ui.erase.disabled = busy;
}

const terminal = {
  clean() {},
  writeLine(s) { log(s); },
  write(s) { log(s); },
};

async function disconnect() {
  try {
    if (transport) await transport.disconnect();
  } catch (e) {
    log("disconnect: " + e);
  }
  transport = null;
  loader = null;
  chipInfo = null;
  ui.chip.hidden = true;
  sync();
}

async function connect() {
  ui.done.hidden = true;
  status("");
  let port;
  try {
    port = await navigator.serial.requestPort();
  } catch (e) {
    return; // the user closed the port picker
  }
  busy = true;
  sync();
  try {
    transport = new Transport(port, false);
    loader = new ESPLoader({ transport, baudrate: Number(ui.baud.value), terminal });
    status("Підключення… Якщо не вдається: затисніть BOOT (GPIO0), натисніть і відпустіть RESET (EN), відпустіть BOOT.");
    await loader.main();
    const chip = loader.chip;
    const desc = await chip.getChipDescription(loader);
    const mac = (await chip.readMac(loader)).toLowerCase();
    const rev = chip.getChipRevision ? await chip.getChipRevision(loader) : 0;
    chipInfo = { name: chip.CHIP_NAME, desc, mac, rev, ok: false };
    let problem = "";
    if (chip.CHIP_NAME !== "ESP32") {
      problem = `Це ${chip.CHIP_NAME}, а прилад ZIR-3M зроблено на ESP32 (WROOM). Прошивати не можна.`;
    } else if (rev < MIN_CHIP_REV) {
      problem = `Ревізія чипа v${rev}: bootstrap зібрано для ревізії v${MIN_CHIP_REV} і новіших, на цьому чипі він не запуститься.`;
    } else {
      chipInfo.ok = true;
    }
    $("fl-chip-desc").textContent = desc;
    $("fl-chip-mac").textContent = mac;
    ui.chip.hidden = false;
    status(problem || "Прилад підключено. Оберіть збірку й натисніть «Прошити».", problem ? "err" : "ok");
  } catch (e) {
    log(String(e));
    status("Не вдалося підключитися: " + (e.message || e) +
      ". Перевірте кабель (з даними, а не лише живлення), драйвер CH340/CP210x і що порт не зайнятий іншою програмою (монітор PlatformIO, Arduino).", "err");
    busy = false;
    await disconnect();
    return;
  }
  busy = false;
  sync();
}

async function fetchImage(buildID) {
  const resp = await fetch(`${imagePrefix}${encodeURIComponent(buildID)}/bootstrap.bin`, { credentials: "same-origin", cache: "no-store" });
  if (!resp.ok) throw new Error(`образ не завантажено з сервера: HTTP ${resp.status} ${await resp.text()}`);
  return new Uint8Array(await resp.arrayBuffer());
}

async function report(buildID) {
  const body = new URLSearchParams({ csrf, build_id: buildID, mac: chipInfo.mac, chip: chipInfo.desc, erase: ui.erase.checked ? "1" : "" });
  const resp = await fetch(doneURL, { method: "POST", body, credentials: "same-origin" });
  if (!resp.ok) log("журнал аудиту: HTTP " + resp.status + " " + (await resp.text()));
}

async function flash() {
  const buildID = ui.build.value;
  const version = ui.build.selectedOptions[0].dataset.version;
  if (ui.erase.checked && !confirm("Стерти всю flash? Прилад втратить ключі (identity) і його доведеться зареєструвати заново.")) {
    return;
  }
  busy = true;
  sync();
  ui.done.hidden = true;
  ui.progress.value = 0;
  ui.progress.hidden = false;
  try {
    status(`Завантаження bootstrap ${version} з сервера…`);
    const data = await fetchImage(buildID);
    status(ui.erase.checked ? "Стирання flash і запис… не від'єднуйте прилад." : "Запис… не від'єднуйте прилад.");
    await loader.writeFlash({
      fileArray: [{ data, address: 0x0 }],
      flashMode: "keep",
      flashFreq: "keep",
      flashSize: "keep",
      eraseAll: ui.erase.checked,
      compress: true,
      reportProgress: (_i, written, total) => {
        ui.progress.value = total ? written / total : 0;
      },
      calculateMD5Hash: md5hex,
    });
    ui.progress.value = 1;
    await loader.after("hard_reset");
    await report(buildID);
    status("");
    $("fl-done-version").textContent = version;
    $("fl-done-mac").textContent = chipInfo.mac;
    ui.done.hidden = false;
  } catch (e) {
    log(String(e));
    status("Помилка запису: " + (e.message || e) + ". Прилад не пошкоджено: прошийте ще раз.", "err");
  }
  busy = false;
  await disconnect();
}

function init() {
  if (!("serial" in navigator)) {
    status(window.isSecureContext
      ? "Цей браузер не підтримує Web Serial. Відкрийте сторінку в Chrome, Edge або Opera на комп'ютері."
      : "Web Serial працює лише через HTTPS (або на localhost). Відкрийте адмінку за адресою https://…", "err");
    ui.connect.disabled = true;
    ui.flash.disabled = true;
    ui.disconnect.disabled = true;
    return;
  }
  ui.connect.addEventListener("click", connect);
  ui.flash.addEventListener("click", flash);
  ui.disconnect.addEventListener("click", disconnect);
  ui.build.addEventListener("change", sync);
  navigator.serial.addEventListener("disconnect", () => {
    if (!busy && loader) {
      log("порт від'єднано");
      disconnect();
    }
  });
  window.addEventListener("beforeunload", (e) => {
    if (busy) e.preventDefault();
  });
  sync();
}

// ── MD5 (RFC 1321) for esptool's post-write verification ────────────────────

const K = new Int32Array(64).map((_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) | 0);
const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

function md5hex(input) {
  const len = input.length;
  const padded = new Uint8Array(((len + 8) >> 6) * 64 + 64);
  padded.set(input);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, (len * 8) >>> 0, true);
  dv.setUint32(padded.length - 4, Math.floor(len / 2 ** 29), true);
  let a0 = 0x67452301, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476;
  const M = new Int32Array(16);
  for (let off = 0; off < padded.length; off += 64) {
    for (let j = 0; j < 16; j++) M[j] = dv.getInt32(off + j * 4, true);
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f, g;
      const r = i >> 4;
      if (r === 0) { f = (b & c) | (~b & d); g = i; }
      else if (r === 1) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
      else if (r === 2) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
      else { f = c ^ (b | ~d); g = (7 * i) & 15; }
      const t = d;
      d = c;
      c = b;
      const x = (a + f + K[i] + M[g]) | 0;
      const s = S[(r << 2) | (i & 3)];
      b = (b + ((x << s) | (x >>> (32 - s)))) | 0;
      a = t;
    }
    a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
  }
  const out = new DataView(new ArrayBuffer(16));
  [a0, b0, c0, d0].forEach((v, i) => out.setInt32(i * 4, v, true));
  return Array.from(new Uint8Array(out.buffer), (x) => x.toString(16).padStart(2, "0")).join("");
}

init();
