// ==== TikTok + Deezer → Telegram relay bot ====
// Отдельный, самостоятельный бот (не связан с основным ботом-персоной).
// Хозяин присылает боту:
//   - ссылку на TikTok (или сразу видеофайл) — бот скачивает ролик через
//     yt-dlp и по кнопке отправляет его в один из подключённых каналов;
//   - ссылку на трек Deezer — бот дёргает свой dzmedia-сервер (см.
//     DEEZER_API_URL/DEEZER_ARL ниже) и присылает готовый MP3/FLAC;
//   - любой другой текст — воспринимает как поиск трека по названию на
//     Deezer и предлагает выбрать нужный вариант кнопками.
// Во всех случаях итоговый файл отправляется в один из подключённых
// каналов от имени бота — как обычное видео/аудио.
//
// Правило "кто качает файл" одинаковое для видео и аудио:
//   - если файл влезает в лимит Telegram Bot API на скачивание по ссылке
//     (~20 МБ) — ссылку просто отдают Telegram'у, и он сам её скачивает
//     (для TikTok — это прямой CDN-URL из yt-dlp, для Deezer — ссылка на
//     /download нашего dzmedia-сервера);
//   - если файл больше (до 50 МБ — абсолютный лимит Bot API на загрузку) —
//     файл качает и грузит в Telegram сам "сервер": для TikTok это сам этот
//     бот (как и раньше — yt-dlp качает локально, потом sendVideo файлом),
//     а для Deezer — это отдельный dzmedia-сервер через свой /send_audio
//     (у него для этого должен быть свой BOT_TOKEN, см. .env.example); если
//     он недоступен/не настроен — бот всё равно подстрахуется и скачает
//     трек сам.
//
// Качество Deezer-треков (FLAC / MP3 320 / MP3 128) переключается прямо в
// Telegram командой /quality, по умолчанию — MP3 320 кбит/с.
//
// Регистрация каналов — два способа, оба не требуют "ждать новый пост":
//   1. Добавь бота админом в канал — придёт апдейт my_chat_member,
//      бот сам себя зарегистрирует.
//   2. Перешли боту в личку любое старое сообщение ИЗ канала —
//      бот прочитает forward_origin и зарегистрирует канал тоже.
// Отправлять в канал бот всё равно сможет только если он там админ —
// это ограничение самого Telegram, не обходится никаким кодом.

import { Bot, InputFile } from "grammy";
import { Redis } from "@upstash/redis";
import { spawn } from "node:child_process";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import http from "node:http";

const BOT_TOKEN = process.env.BOT_TOKEN;
const OWNER_ID = Number(process.env.OWNER_ID);

if (!BOT_TOKEN) throw new Error("Нужен BOT_TOKEN в переменных окружения");
if (!OWNER_ID) throw new Error("Нужен OWNER_ID (числовой Telegram id хозяина) в переменных окружения");

// Redis.fromEnv() сам берёт UPSTASH_REDIS_REST_URL и UPSTASH_REDIS_REST_TOKEN.
// Без них бот тоже работает, просто список каналов и выбранное качество
// не переживут рестарт — для хобби-проекта на бесплатном Render это не
// критично, но лучше настроить.
const redis =
  process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN ? Redis.fromEnv() : null;
if (!redis) {
  console.warn("Upstash Redis не настроен — список каналов и качество Deezer будут жить только в памяти процесса");
}

const bot = new Bot(BOT_TOKEN);

// chatId -> title
const channels = new Map();

async function saveChannels() {
  if (!redis) return;
  try {
    await redis.set("channels", Object.fromEntries(channels));
  } catch (err) {
    console.error("Redis: не удалось сохранить список каналов:", err);
  }
}

async function loadChannels() {
  if (!redis) return;
  try {
    const saved = await redis.get("channels");
    if (saved && typeof saved === "object") {
      for (const [chatIdRaw, title] of Object.entries(saved)) {
        channels.set(Number(chatIdRaw), title);
      }
    }
  } catch (err) {
    console.error("Redis: не удалось загрузить список каналов:", err);
  }
}

function isOwner(ctx) {
  return ctx.from && ctx.from.id === OWNER_ID;
}

function registerChannel(chatId, title) {
  const changed = channels.get(chatId) !== title;
  channels.set(chatId, title);
  if (changed) saveChannels();
}

// ---- Автоматическая регистрация каналов ----

// Способ 1: бота сделали админом канала — Telegram сам присылает апдейт.
bot.on("my_chat_member", async (ctx) => {
  const chat = ctx.chatMember.chat;
  if (chat.type !== "channel") return;
  const status = ctx.chatMember.new_chat_member.status;
  if (status === "administrator" || status === "creator") {
    registerChannel(chat.id, chat.title || String(chat.id));
    if (OWNER_ID) {
      bot.api
        .sendMessage(OWNER_ID, `✅ добавлен как админ в канал «${chat.title}» — зарегистрировал`)
        .catch(() => {});
    }
  } else if (status === "left" || status === "kicked") {
    if (channels.delete(chat.id)) saveChannels();
  }
});

// Способ 2: переслали любое старое сообщение из канала в личку боту —
// достаточно, чтобы узнать chat_id и title, посту необязательно быть новым.
function extractForwardedChannel(msg) {
  // Bot API 7.x+: forward_origin. Более старые клиенты/боты — forward_from_chat.
  const origin = msg.forward_origin;
  if (origin && origin.type === "channel" && origin.chat) {
    return origin.chat;
  }
  if (msg.forward_from_chat && msg.forward_from_chat.type === "channel") {
    return msg.forward_from_chat;
  }
  return null;
}

// ---- Общие лимиты Telegram Bot API ----

// Если боту дать вместо файла HTTP-ссылку, Telegram сам скачает файл со
// своей стороны — но только если он не тяжелее примерно 20 МБ. Больше —
// нужно скачать самим и загрузить как обычный файл (multipart), а это уже
// упирается в абсолютный лимит Bot API на загрузку — 50 МБ.
const TELEGRAM_URL_FETCH_LIMIT_BYTES = 20 * 1024 * 1024;
const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;

// ---- Скачивание с TikTok: tikwm.com (без вотемарки, свой CDN) + yt-dlp как фолбэк ----

const TIKTOK_URL_REGEX = /https?:\/\/(?:www\.|vt\.|vm\.|m\.)?tiktok\.com\/\S+/i;

// tikwm.com — бесплатный резолвер без ключа: отдаёт ссылки на СВОЁМ CDN, а не
// на прямом CDN TikTok, поэтому Telegram может их скачать без Referer/UA,
// которые TikTok иначе требует. hdplay/play — БЕЗ вотемарки (HD и SD
// соответственно), wmplay — с вотемаркой, её никогда не берём.
async function getTikTokDirectInfoTikwm(url) {
  const res = await fetch(`https://www.tikwm.com/api/?url=${encodeURIComponent(url)}&hd=1`, {
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`tikwm ответил ${res.status}`);
  const json = await res.json();
  if (json.code !== 0 || !json.data) throw new Error(json.msg || "tikwm: пустой ответ");
  const data = json.data;
  const directUrl = data.hdplay || data.play;
  if (!directUrl) throw new Error("tikwm: нет ссылки без вотемарки для этого видео");
  const filesize = (data.hdplay ? data.hd_size : data.size) || null;
  return { directUrl, filesize };
}

// yt-dlp как запасной резолвер, если tikwm недоступен/не смог разобрать ссылку.
async function getTikTokDirectInfoYtDlp(url) {
  return new Promise((resolve, reject) => {
    const proc = spawn("yt-dlp", ["--no-playlist", "--no-warnings", "-j", url]);
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (chunk) => (stdout += chunk.toString()));
    proc.stderr.on("data", (chunk) => (stderr += chunk.toString()));
    proc.on("error", (err) => reject(err));
    proc.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr.trim().split("\n").pop() || `yt-dlp завершился с кодом ${code}`));
        return;
      }
      try {
        const lastLine = stdout.trim().split("\n").pop();
        const info = JSON.parse(lastLine);
        resolve({
          directUrl: info.url || null,
          filesize: info.filesize || info.filesize_approx || null,
        });
      } catch (err) {
        reject(err);
      }
    });
  });
}

// Быстрый режим без скачивания: сначала tikwm (без вотемарки, свой CDN —
// Telegram скачает по ссылке без проблем), при ошибке — yt-dlp.
async function getTikTokDirectInfo(url) {
  try {
    return await getTikTokDirectInfoTikwm(url);
  } catch (err) {
    console.warn("tikwm не смог разобрать ссылку, пробую yt-dlp:", err.message || err);
    return getTikTokDirectInfoYtDlp(url);
  }
}

// Качает файл по уже известной прямой ссылке (tikwm) — без запуска yt-dlp.
async function downloadFromUrl(directUrl, destPath) {
  const res = await fetch(directUrl, { signal: AbortSignal.timeout(120_000) });
  if (!res.ok) throw new Error(`скачивание по прямой ссылке: ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  await writeFile(destPath, buf);
  return destPath;
}

async function downloadTikTokYtDlp(url, destDir) {
  const outputTemplate = path.join(destDir, "video.%(ext)s");
  return new Promise((resolve, reject) => {
    const proc = spawn("yt-dlp", [
      "--no-playlist",
      "--output",
      outputTemplate,
      "--merge-output-format",
      "mp4",
      url,
    ]);
    let stderr = "";
    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    proc.on("error", (err) => reject(err)); // yt-dlp не найден и т.п.
    proc.on("close", (code) => {
      if (code === 0) resolve(path.join(destDir, "video.mp4"));
      else reject(new Error(stderr.trim().split("\n").pop() || `yt-dlp завершился с кодом ${code}`));
    });
  });
}

// knownDirectUrl — если уже резолвили через tikwm раньше (например, при
// первой попытке "дать ссылку Telegram'у"), не резолвим второй раз, а сразу
// пробуем скачать её сами; если и это не вышло — честный yt-dlp с нуля.
async function downloadTikTok(url, destDir, knownDirectUrl = null) {
  if (knownDirectUrl) {
    try {
      return await downloadFromUrl(knownDirectUrl, path.join(destDir, "video.mp4"));
    } catch (err) {
      console.warn("Не вышло скачать по прямой ссылке tikwm, пробую yt-dlp:", err.message || err);
    }
  } else {
    try {
      const info = await getTikTokDirectInfoTikwm(url);
      return await downloadFromUrl(info.directUrl, path.join(destDir, "video.mp4"));
    } catch (err) {
      console.warn("tikwm не помог со скачиванием, пробую yt-dlp:", err.message || err);
    }
  }
  return downloadTikTokYtDlp(url, destDir);
}

async function sendTikTokVideoLocally(sourceUrl, targetChatId, knownDirectUrl = null) {
  const tmpDir = await mkdtemp(path.join(tmpdir(), "ttvideo-"));
  try {
    const filePath = await downloadTikTok(sourceUrl, tmpDir, knownDirectUrl);
    const { size } = await stat(filePath);
    if (size > MAX_UPLOAD_BYTES) {
      throw new Error(
        `видео весит ${(size / 1024 / 1024).toFixed(1)} МБ — больше лимита Telegram Bot API (50 МБ)`
      );
    }
    await bot.api.sendVideo(targetChatId, new InputFile(filePath));
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}

// ---- Deezer: конфигурация dzmedia-сервера (см. отдельный Rust-проект) ----
//
// DEEZER_API_URL — базовый URL твоего задеплоенного dzmedia (Fly.io/HF Space/…),
//   без слэша на конце, напр. https://dzmedia.fly.dev
// DEEZER_ARL     — ARL-кука аккаунта Deezer (нужна серверу, чтобы получать
//   ссылки на реальные аудио и расшифровывать их); без неё скачивание работать
//   не будет — сервер вернёт "arl required".
// DEEZER_FORMAT  — стартовое качество по умолчанию: MP3_320 / FLAC / MP3_128.
//   Дальше переключается прямо в Telegram командой /quality — выбор
//   сохраняется (в Redis, если настроен) и переживает рестарт.
// DEEZER_SEND_AUDIO_TIMEOUT_MS — сколько ждать ответа от /send_audio
//   dzmedia-сервера (он сам скачивает, тегирует и грузит трек в Telegram —
//   это может занять время), по умолчанию 60 секунд.
const DEEZER_API_URL = (process.env.DEEZER_API_URL || "").replace(/\/+$/, "");
const DEEZER_ARL = process.env.DEEZER_ARL || "";
const DEEZER_ENABLED = Boolean(DEEZER_API_URL && DEEZER_ARL);
const DEEZER_SEND_AUDIO_TIMEOUT_MS = Number(process.env.DEEZER_SEND_AUDIO_TIMEOUT_MS || 60_000);

if (!DEEZER_ENABLED) {
  console.warn(
    "DEEZER_API_URL / DEEZER_ARL не заданы — поддержка Deezer (ссылки и поиск) выключена"
  );
}

const DEEZER_TRACK_URL_REGEX = /https?:\/\/(?:www\.)?deezer\.com\/(?:[a-z]{2}\/)?track\/(\d+)/i;
const DEEZER_SHORT_URL_REGEX = /https?:\/\/(?:deezer\.page\.link|dzr\.page\.link|link\.deezer\.com)\/\S+/i;

const DEEZER_FORMAT_OPTIONS = ["FLAC", "MP3_320", "MP3_128"];
const DEEZER_FORMAT_LABELS = {
  FLAC: "FLAC (без потерь)",
  MP3_320: "MP3 320 кбит/с",
  MP3_128: "MP3 128 кбит/с",
};
// Грубая, специально завышенная для FLAC оценка среднего битрейта — нужна
// только чтобы решить, влезет ли трек в 20 МБ для скачивания по ссылке;
// не влияет на реальное качество файла, только на выбор способа доставки.
const DEEZER_FORMAT_BITRATE_KBPS = { FLAC: 1100, MP3_320: 320, MP3_128: 128 };

let deezerFormat = (process.env.DEEZER_FORMAT || "MP3_320").toUpperCase();
if (!DEEZER_FORMAT_OPTIONS.includes(deezerFormat)) deezerFormat = "MP3_320";

function getDeezerFormat() {
  return deezerFormat;
}

async function setDeezerFormat(format) {
  if (!DEEZER_FORMAT_OPTIONS.includes(format)) return;
  deezerFormat = format;
  if (!redis) return;
  try {
    await redis.set("deezerFormat", format);
  } catch (err) {
    console.error("Redis: не удалось сохранить качество Deezer:", err);
  }
}

async function loadDeezerFormat() {
  if (!redis) return;
  try {
    const saved = await redis.get("deezerFormat");
    if (saved && DEEZER_FORMAT_OPTIONS.includes(saved)) {
      deezerFormat = saved;
    }
  } catch (err) {
    console.error("Redis: не удалось загрузить качество Deezer:", err);
  }
}

function buildQualityKeyboard() {
  const rows = DEEZER_FORMAT_OPTIONS.map((format) => [
    {
      text: `${format === deezerFormat ? "✅ " : ""}${DEEZER_FORMAT_LABELS[format]}`,
      callback_data: `dzquality:${format}`,
    },
  ]);
  return { inline_keyboard: rows };
}

// ---- Deezer: резолв ссылки, поиск, метаданные, скачивание через dzmedia ----

// Короткие share-ссылки (deezer.page.link/…) редиректят на обычный
// /track/<id> — просто идём по редиректу и вытаскиваем id из финального URL.
async function resolveDeezerTrackId(url) {
  const direct = url.match(DEEZER_TRACK_URL_REGEX);
  if (direct) return direct[1];

  if (DEEZER_SHORT_URL_REGEX.test(url)) {
    try {
      const res = await fetch(url, { redirect: "follow" });
      const finalUrl = res.url || url;
      const resolved = finalUrl.match(DEEZER_TRACK_URL_REGEX);
      if (resolved) return resolved[1];
    } catch (err) {
      console.error("Не удалось развернуть короткую ссылку Deezer:", err);
    }
  }
  return null;
}

// Публичное Deezer API (api.deezer.com) не требует авторизации и подходит
// и для метаданных по id, и для поиска по названию — ARL для него не нужен,
// он нужен только dzmedia-серверу, когда доходит до реальной ссылки на аудио.
async function fetchDeezerTrackMeta(id) {
  const res = await fetch(`https://api.deezer.com/track/${id}`);
  if (!res.ok) throw new Error(`deezer api: ${res.status}`);
  const data = await res.json();
  if (data.error) throw new Error(data.error.message || "deezer api error");
  return {
    id: String(data.id),
    title: data.title || "",
    performer: data.artist?.name || "",
    album: data.album?.title || "",
    duration: data.duration || 0,
    coverUrl: data.album?.cover_big || data.album?.cover_medium || "",
  };
}

async function searchDeezerTracks(query, limit = 8) {
  const res = await fetch(`https://api.deezer.com/search?q=${encodeURIComponent(query)}&limit=${limit}`);
  if (!res.ok) throw new Error(`deezer search: ${res.status}`);
  const data = await res.json();
  return (data.data || []).map((t) => ({
    id: String(t.id),
    title: t.title || "",
    performer: t.artist?.name || "",
    album: t.album?.title || "",
    duration: t.duration || 0,
    coverUrl: t.album?.cover_medium || "",
  }));
}

function buildDeezerParams(meta, format, extra = {}) {
  const params = new URLSearchParams({ id: meta.id, format, arl: DEEZER_ARL, ...extra });
  if (meta.title) params.set("title", meta.title);
  if (meta.performer) params.set("performer", meta.performer);
  if (meta.album) params.set("album", meta.album);
  if (meta.coverUrl) params.set("cover_url", meta.coverUrl);
  return params;
}

// /stream (в отличие от /download) сначала проверяет прогретый CDN-кэш и умеет
// отдавать файл потоком с поддержкой Range — используется только внутренним
// фоллбэком (downloadDeezerTrack/sendDeezerTrackLocally), никогда как ссылка
// напрямую для Telegram: dzmedia специально не торчит наружу (слушает только
// 127.0.0.1:8080 внутри этого же контейнера, см. entrypoint.sh и
// .env.example) — такая ссылка для Telegram в принципе недостижима. Плюс это
// архитектурно и не нужно: /stream/download несут ARL (сессионную куку
// Deezer-аккаунта) в query-параметрах, и если бы dzmedia был доступен
// снаружи, эта ARL улетала бы прямо в URL, который видит Telegram. Поэтому
// трек всегда доставляется через sendBigDeezerTrack: dzmedia сам скачивает,
// расшифровывает и грузит в Telegram своим BOT_TOKEN (ARL наружу не уходит),
// а при неудаче — бот подстраховывается и качает готовый расшифрованный
// поток по этой internal-ссылке сам.
function buildDeezerStreamUrl(meta, format) {
  return `${DEEZER_API_URL}/stream?${buildDeezerParams(meta, format).toString()}`;
}


// Просит dzmedia заранее резолвнуть и закэшировать CDN-ссылку (см. /warm на
// сервере), пока пользователь ещё выбирает канал — чтобы к моменту, когда
// Telegram полезет за файлом по /stream, кэш был уже тёплым. Best-effort:
// ошибку тут проглатываем, /stream в любом случае справится сам, просто
// медленнее.
function warmDeezerTrack(meta, format) {
  if (!DEEZER_ENABLED) return;
  const url = `${DEEZER_API_URL}/warm?${buildDeezerParams(meta, format).toString()}`;
  fetch(url).catch((err) => {
    console.warn("Не удалось прогреть кэш dzmedia:", err.message || err);
  });
}

// Скачивает расшифрованный трек через dzmedia /download на диск бота —
// используется только как подстраховка (когда Telegram не смог сам
// скачать файл по ссылке, или когда /send_audio недоступен).
async function downloadDeezerTrack(meta, destDir, format) {
  if (!DEEZER_ENABLED) {
    throw new Error("Deezer не настроен: нужны DEEZER_API_URL и DEEZER_ARL");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120_000); // decrypt на сервере может занять время
  let res;
  try {
    res = await fetch(buildDeezerStreamUrl(meta, format), { signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || `dzmedia ответил ${res.status}`);
  }

  const disposition = res.headers.get("content-disposition") || "";
  const nameMatch = disposition.match(/filename="([^"]+)"/);
  const extFromName = nameMatch ? path.extname(nameMatch[1]).slice(1) : "";
  const ext = extFromName || ((res.headers.get("content-type") || "").includes("flac") ? "flac" : "mp3");

  const buf = Buffer.from(await res.arrayBuffer());
  const filePath = path.join(destDir, `track.${ext}`);
  await writeFile(filePath, buf);
  return filePath;
}

async function sendDeezerTrackLocally(meta, format, targetChatId) {
  const tmpDir = await mkdtemp(path.join(tmpdir(), "dztrack-"));
  try {
    const filePath = await downloadDeezerTrack(meta, tmpDir, format);
    const { size } = await stat(filePath);
    if (size > MAX_UPLOAD_BYTES) {
      throw new Error(
        `трек весит ${(size / 1024 / 1024).toFixed(1)} МБ — больше лимита Telegram Bot API (50 МБ), попробуй качество ниже`
      );
    }
    await bot.api.sendAudio(targetChatId, new InputFile(filePath), {
      title: meta.title || undefined,
      performer: meta.performer || undefined,
      duration: meta.duration || undefined,
    });
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}

// "Большой" трек — просим сам dzmedia-сервер скачать, расшифровать,
// затегировать и загрузить в Telegram (у него свой BOT_TOKEN, см.
// .env.example у dzmedia). Если это не получилось (например, BOT_TOKEN там
// не настроен) — подстраховываемся и качаем/грузим сами.
async function sendBigDeezerTrack(meta, format, targetChatId) {
  const params = new URLSearchParams({
    id: meta.id,
    format,
    arl: DEEZER_ARL,
    chat_id: String(targetChatId),
  });
  if (meta.title) params.set("title", meta.title);
  if (meta.performer) params.set("performer", meta.performer);
  if (meta.album) params.set("album", meta.album);
  if (meta.coverUrl) params.set("cover_url", meta.coverUrl);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DEEZER_SEND_AUDIO_TIMEOUT_MS);
  try {
    let res;
    try {
      res = await fetch(`${DEEZER_API_URL}/send_audio?${params.toString()}`, { signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
    const body = await res.json().catch(() => ({}));
    if (!res.ok || body.error) {
      throw new Error(body.error || `dzmedia ответил ${res.status}`);
    }
  } catch (err) {
    console.warn("dzmedia /send_audio не сработал, качаю и гружу трек сам:", err.message || err);
    await sendDeezerTrackLocally(meta, format, targetChatId);
  }
}

// Решает маршрут (ссылка на dzmedia vs "пусть сервер сам отправит") и сразу
// предлагает выбрать канал — реальное скачивание/загрузка произойдёт только
// после того, как канал выбран.
async function offerDeezerTrack(ctx, meta, statusMsg) {
  const format = getDeezerFormat();

  await ctx.api.deleteMessage(ctx.chat.id, statusMsg.message_id).catch(() => {});

  // Греем кэш CDN-ссылки на всякий случай, пока пользователь выбирает канал —
  // если sendBigDeezerTrack не сработает и придётся идти через фоллбэк
  // (downloadDeezerTrack, использует /stream), кэш уже будет тёплым.
  warmDeezerTrack(meta, format);

  await offerChannelChoice(ctx, {
    kind: "audio-big",
    meta,
    format,
  });
}

async function handleDeezerLink(ctx, url) {
  if (!DEEZER_ENABLED) {
    await ctx.reply("Deezer не настроен: нужны DEEZER_API_URL и DEEZER_ARL в переменных окружения");
    return;
  }
  const statusMsg = await ctx.reply("ищу трек…");
  const trackId = await resolveDeezerTrackId(url);
  if (!trackId) {
    await ctx.api.editMessageText(ctx.chat.id, statusMsg.message_id, "не смог распознать ссылку на трек Deezer");
    return;
  }
  let meta;
  try {
    meta = await fetchDeezerTrackMeta(trackId);
  } catch (err) {
    console.error("Не удалось получить метаданные трека Deezer:", err);
    await ctx.api.editMessageText(ctx.chat.id, statusMsg.message_id, `не вышло найти трек: ${err.message || err}`);
    return;
  }
  await offerDeezerTrack(ctx, meta, statusMsg);
}

// ownerId -> результаты последнего поиска (для callback dzpick:<index>)
const pendingSearch = new Map();

async function handleDeezerSearch(ctx, query) {
  if (!DEEZER_ENABLED) return; // тихо игнорируем, чтобы не мешать обычной переписке
  let results;
  try {
    results = await searchDeezerTracks(query);
  } catch (err) {
    console.error("Ошибка поиска Deezer:", err);
    await ctx.reply(`не вышло поискать на Deezer: ${err.message || err}`);
    return;
  }
  if (results.length === 0) {
    await ctx.reply("по этому запросу Deezer ничего не нашёл");
    return;
  }
  pendingSearch.set(ctx.from.id, results);
  const rows = results.map((t, i) => [
    { text: `${t.performer} — ${t.title}`.slice(0, 64), callback_data: `dzpick:${i}` },
  ]);
  await ctx.reply("нашёл на Deezer, выбери трек:", { reply_markup: { inline_keyboard: rows } });
}

// ---- Выбор канала для отправки ----

// ownerId -> { kind, filePath?/fileId?/url?, meta?, format?, ... }
const pendingSend = new Map();

function buildChannelKeyboard() {
  const rows = [...channels.entries()]
    .sort((a, b) => a[1].localeCompare(b[1], "ru"))
    .map(([chatId, title]) => [{ text: title.slice(0, 64), callback_data: `sendto:${chatId}` }]);
  return { inline_keyboard: rows };
}

async function offerChannelChoice(ctx, payload) {
  if (channels.size === 0) {
    await ctx.reply(
      "не знаю ни одного канала — добавь меня админом в канал, или перешли мне любое сообщение из него"
    );
    return;
  }
  pendingSend.set(ctx.from.id, payload);
  await ctx.reply("куда отправить?", { reply_markup: buildChannelKeyboard() });
}

// ---- Команды и хендлеры ----

bot.command("start", async (ctx) => {
  if (!isOwner(ctx)) {
    await ctx.reply("этот бот приватный");
    return;
  }
  await ctx.reply(
    "пришли ссылку на TikTok (или сразу видео), ссылку на трек Deezer, " +
      "или просто название трека для поиска на Deezer — предложу, в какой канал отправить.\n\n" +
      "/quality — выбрать качество для треков Deezer (по умолчанию 320 кбит/с).\n\n" +
      "чтобы бот мог постить в канал: добавь его туда админом, или перешли мне сюда любое сообщение из этого канала (для регистрации не обязательно новое)."
  );
});

bot.command("channels", async (ctx) => {
  if (!isOwner(ctx)) return;
  if (channels.size === 0) {
    await ctx.reply("каналов пока нет");
    return;
  }
  const list = [...channels.entries()].map(([id, title]) => `• ${title} (${id})`).join("\n");
  await ctx.reply(`известные каналы:\n${list}`);
});

bot.command("quality", async (ctx) => {
  if (!isOwner(ctx)) return;
  if (!DEEZER_ENABLED) {
    await ctx.reply("Deezer не настроен — качество менять пока не на чем");
    return;
  }
  await ctx.reply(`сейчас: ${DEEZER_FORMAT_LABELS[deezerFormat]}\nвыбери качество для новых треков:`, {
    reply_markup: buildQualityKeyboard(),
  });
});

// Прямая видео/документ отправка боту — сразу предлагаем выбор канала
// по file_id, без скачивания (файл уже на серверах Telegram).
bot.on(["message:video", "message:animation", "message:document"], async (ctx) => {
  if (!isOwner(ctx)) return;

  const forwardedChannel = extractForwardedChannel(ctx.message);
  if (forwardedChannel) {
    registerChannel(forwardedChannel.id, forwardedChannel.title || String(forwardedChannel.id));
    await ctx.reply(`канал «${forwardedChannel.title}» зарегистрирован`);
    return;
  }

  const fileId = ctx.message.video?.file_id || ctx.message.animation?.file_id || ctx.message.document?.file_id;
  const kind = ctx.message.video ? "video" : ctx.message.animation ? "animation" : "document";
  await offerChannelChoice(ctx, { fileId, kind });
});

// Пытаемся получить прямую ссылку на видео без скачивания. Если её размер
// известен и укладывается в лимит на скачивание по ссылке — Telegram
// скачает сам; иначе (размер неизвестен или видео большое) качаем сами, как
// раньше, и грузим уже готовым файлом.
async function handleTikTokLink(ctx, url) {
  const statusMsg = await ctx.reply("проверяю ссылку…");

  let info = null;
  try {
    info = await getTikTokDirectInfo(url);
  } catch (err) {
    console.warn("Не удалось получить информацию о TikTok-видео заранее:", err.message || err);
  }

  if (info?.directUrl && info.filesize && info.filesize <= TELEGRAM_URL_FETCH_LIMIT_BYTES) {
    await ctx.api.deleteMessage(ctx.chat.id, statusMsg.message_id).catch(() => {});
    await offerChannelChoice(ctx, { kind: "video-url", url: info.directUrl, sourceUrl: url });
    return;
  }

  await ctx.api.editMessageText(ctx.chat.id, statusMsg.message_id, "скачиваю…").catch(() => {});
  const tmpDir = await mkdtemp(path.join(tmpdir(), "ttvideo-"));
  try {
    const filePath = await downloadTikTok(url, tmpDir, info?.directUrl || null);
    const { size } = await stat(filePath);
    if (size > MAX_UPLOAD_BYTES) {
      await ctx.api.editMessageText(
        ctx.chat.id,
        statusMsg.message_id,
        `видео весит ${(size / 1024 / 1024).toFixed(1)} МБ — это больше лимита Telegram Bot API на загрузку (50 МБ), отправить не получится`
      );
      await rm(tmpDir, { recursive: true, force: true });
      return;
    }
    await ctx.api.deleteMessage(ctx.chat.id, statusMsg.message_id).catch(() => {});
    await offerChannelChoice(ctx, { filePath, kind: "video" });
  } catch (err) {
    console.error("Не удалось скачать TikTok-видео:", err);
    await ctx.api.editMessageText(
      ctx.chat.id,
      statusMsg.message_id,
      `не вышло скачать: ${err.message || err}`
    );
    await rm(tmpDir, { recursive: true, force: true });
  }
}

bot.on("message:text", async (ctx) => {
  if (!isOwner(ctx)) return;

  const forwardedChannel = extractForwardedChannel(ctx.message);
  if (forwardedChannel) {
    registerChannel(forwardedChannel.id, forwardedChannel.title || String(forwardedChannel.id));
    await ctx.reply(`канал «${forwardedChannel.title}» зарегистрирован`);
    return;
  }

  const text = ctx.message.text.trim();
  if (text.startsWith("/")) return; // неизвестная команда — не наш случай

  const tiktokMatch = text.match(TIKTOK_URL_REGEX);
  if (tiktokMatch) {
    await handleTikTokLink(ctx, tiktokMatch[0]);
    return;
  }

  const isDeezerLink = DEEZER_TRACK_URL_REGEX.test(text) || DEEZER_SHORT_URL_REGEX.test(text);
  if (isDeezerLink) {
    await handleDeezerLink(ctx, text);
    return;
  }

  // Ничего похожего на ссылку — считаем текст запросом поиска трека на Deezer.
  await handleDeezerSearch(ctx, text);
});

bot.on("callback_query:data", async (ctx) => {
  const data = ctx.callbackQuery.data;

  // Переключение качества Deezer.
  if (data.startsWith("dzquality:")) {
    if (!isOwner(ctx)) {
      await ctx.answerCallbackQuery({ text: "это приватный бот", show_alert: true });
      return;
    }
    const format = data.slice("dzquality:".length);
    await setDeezerFormat(format);
    await ctx
      .editMessageText(`качество для новых треков: ${DEEZER_FORMAT_LABELS[deezerFormat]}`, {
        reply_markup: buildQualityKeyboard(),
      })
      .catch(() => {});
    await ctx.answerCallbackQuery({ text: "готово" });
    return;
  }

  // Выбор трека из результатов поиска Deezer.
  if (data.startsWith("dzpick:")) {
    if (!isOwner(ctx)) {
      await ctx.answerCallbackQuery({ text: "это приватный бот", show_alert: true });
      return;
    }
    const idx = Number(data.slice("dzpick:".length));
    const results = pendingSearch.get(ctx.from.id);
    if (!results || !results[idx]) {
      await ctx.answerCallbackQuery({ text: "сессия устарела, ищи заново", show_alert: true });
      return;
    }
    pendingSearch.delete(ctx.from.id);
    await ctx.answerCallbackQuery();
    const meta = results[idx];
    await offerDeezerTrack(ctx, meta, ctx.callbackQuery.message);
    return;
  }

  if (!data.startsWith("sendto:")) return;

  if (!isOwner(ctx)) {
    await ctx.answerCallbackQuery({ text: "это приватный бот", show_alert: true });
    return;
  }

  const pending = pendingSend.get(ctx.from.id);
  if (!pending) {
    await ctx.answerCallbackQuery({ text: "сессия устарела, пришли ссылку/файл заново", show_alert: true });
    return;
  }
  pendingSend.delete(ctx.from.id);

  // Отвечаем на callback сразу, не дожидаясь отправки: скачивание/загрузка
  // файла (особенно локальный фоллбэк) может занять дольше, чем Telegram
  // готов ждать ответа на callback_query, и тогда answerCallbackQuery падает
  // с "query is too old" — раньше это происходило уже в catch-блоке ниже,
  // без обработчика ошибок бота, и роняло весь процесс.
  await ctx.answerCallbackQuery().catch(() => {});

  const targetChatId = Number(data.slice("sendto:".length));
  const targetTitle = channels.get(targetChatId) || String(targetChatId);

  try {
    if (pending.kind === "audio-big") {
      // dzmedia сам качает/тегирует/грузит трек в Telegram по chat_id.
      await sendBigDeezerTrack(pending.meta, pending.format, targetChatId);
    } else if (pending.kind === "audio-url") {
      // Даём Telegram'у ссылку на dzmedia /download — он скачает сам.
      try {
        await bot.api.sendAudio(targetChatId, pending.url, {
          title: pending.meta.title || undefined,
          performer: pending.meta.performer || undefined,
          duration: pending.meta.duration || undefined,
        });
      } catch (err) {
        console.warn("Telegram не смог скачать трек по ссылке, качаю сам:", err.message || err);
        await sendDeezerTrackLocally(pending.meta, pending.format, targetChatId);
      }
    } else if (pending.kind === "video-url") {
      // Даём Telegram'у прямую ссылку на TikTok CDN — он скачает сам.
      try {
        await bot.api.sendVideo(targetChatId, pending.url);
      } catch (err) {
        console.warn("Telegram не смог скачать видео по ссылке, качаю сам:", err.message || err);
        await sendTikTokVideoLocally(pending.sourceUrl, targetChatId, pending.url);
      }
    } else if (pending.filePath) {
      await bot.api.sendVideo(targetChatId, new InputFile(pending.filePath));
    } else if (pending.kind === "video") {
      await bot.api.sendVideo(targetChatId, pending.fileId);
    } else if (pending.kind === "animation") {
      await bot.api.sendAnimation(targetChatId, pending.fileId);
    } else {
      await bot.api.sendDocument(targetChatId, pending.fileId);
    }
    await ctx.editMessageText(`отправлено в «${targetTitle}»`);
  } catch (err) {
    console.error("Не удалось отправить в канал:", err);
    await ctx.editMessageText(`не вышло отправить в «${targetTitle}», см. логи`).catch(() => {});
  } finally {
    if (pending.filePath) {
      await rm(path.dirname(pending.filePath), { recursive: true, force: true }).catch(() => {});
    }
  }
});

// Render бесплатно даёт только тип "Web Service", а не "Background Worker" —
// у него free-плана вообще нет. Чтобы деплоиться бесплатно, сервис должен
// притворяться веб-сервисом: открыть порт, который Render сканирует при
// старте. Сам бот при этом как работал через long polling, так и работает —
// этот сервер только отвечает "ok" на любой запрос, для health-check'ов.
function startHealthCheckServer() {
  const port = process.env.PORT || 10000;
  http
    .createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    })
    .listen(port, () => {
      console.log(`Health-check сервер слушает порт ${port} (для бесплатного Render Web Service)`);
    });
}

async function main() {
  await loadChannels();
  await loadDeezerFormat();
  await bot.api.setMyCommands([
    { command: "start", description: "как пользоваться" },
    { command: "channels", description: "список известных каналов" },
    { command: "quality", description: "качество треков Deezer" },
  ]);
  console.log(
    `Бот запущен, известно каналов: ${channels.size}, качество Deezer: ${deezerFormat}${
      DEEZER_ENABLED ? "" : " (Deezer выключен)"
    }`
  );
  startHealthCheckServer();
  // Без этого обработчика любая необработанная ошибка в middleware (даже
  // безобидная вроде просроченного callback_query) валит весь процесс —
  // grammY прокидывает её как unhandled rejection, а Node.js завершает работу.
  bot.catch((err) => {
    console.error(`Ошибка при обработке update ${err.ctx?.update?.update_id}:`, err.error || err);
  });

  bot.start();
}

main().catch((err) => {
  console.error("Не удалось запустить бота:", err);
  process.exit(1);
});
