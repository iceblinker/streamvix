import "dotenv/config";
import { addonBuilder, getRouter, Manifest, ContentType, Stream } from "stremio-addon-sdk";
import { getStreamContent, VixCloudStreamInfo, ExtractorConfig } from "./extractor";
import { mapLegacyProviderName, buildUnifiedStreamName, providerLabel } from './utils/unifiedNames';
import * as fs from 'fs';
import { landingTemplate } from './landingPage';
import * as path from 'path';
import express, { Request, Response, NextFunction } from 'express';

import { formatMediaFlowUrl } from './utils/mediaflow';
import { loadDynamicChannels, mergeDynamic, getDynamicFilePath, invalidateDynamicChannels } from './utils/dynamicChannels';

// --- Lightweight declarations to avoid TS complaints if @types/node non installati ---
// (Non sostituiscono l'uso consigliato di @types/node, ma evitano errori bloccanti.)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare const __dirname: string;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare const process: any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare const Buffer: any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare function require(name: string): any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare const global: any;

import { EPGManager } from './utils/epg';
import { exec, execFile, spawn } from 'child_process';
// import { getSponScheduleStream } from './extractors/sponSchedule';
// import { getSportsonlineStream } from './extractors/sportsonline';
const execFilePromise = util.promisify(execFile);
const DEFAULT_VAVOO_UA = 'VAVOO/3.1.21';
import * as crypto from 'crypto';
import * as util from 'util';


// ================= TYPES & INTERFACES =================
interface AddonConfig {
    tmdbApiKey?: string;
    mediaFlowProxyUrl?: string;
    mediaFlowProxyPassword?: string;
    enableMpd?: boolean;

    disableLiveTv?: boolean;
    disableVixsrc?: boolean;
    tvtapProxyEnabled?: boolean;
}

interface VavooCache {
    timestamp: number;
    links: Map<string, string | string[]>;
    updating: boolean;
}

function debugLog(...args: any[]) { try { console.log('[DEBUG]', ...args); } catch { } }


const VAVOO_DEBUG: boolean = (() => {
    try {
        const env = (process && process.env) ? process.env : {} as any;
        const norm = (v?: string) => (v || '').toString().trim().toLowerCase();
        const v1 = norm(env.VAVOO_DEBUG); const v2 = norm(env.DEBUG_VAVOO);
        if (v1) return !(v1 === '0' || v1 === 'false' || v1 === 'off');
        if (v2) return !(v2 === '0' || v2 === 'false' || v2 === 'off');
        return true;
    } catch { return true; }
})();
function vdbg(...args: any[]) { if (!VAVOO_DEBUG) return; try { console.log('[VAVOO-DEBUG]', ...args); } catch { } }

const VAVOO_FORCE_SERVER_IP: boolean = (() => {
    try {
        const env = (process && process.env) ? process.env : {} as any;
        const norm = (v?: string) => (v || '').toString().trim().toLowerCase();
        const v1 = norm(env.VAVOO_FORCE_SERVER_IP); const v2 = norm(env.VAVOO_USE_SERVER_IP);
        if (v1) return !(v1 === '0' || v1 === 'false' || v1 === 'off');
        if (v2) return !(v2 === '0' || v2 === 'false' || v2 === 'off');
        return true;
    } catch { return true; }
})();
const VAVOO_SET_IPLOCATION_ONLY: boolean = (() => { try { const v = (process?.env?.VAVOO_SET_IPLOCATION_ONLY || '').toLowerCase(); if (!v) return true; return !(v === '0' || v === 'false' || v === 'off'); } catch { return false; } })();
const VAVOO_LOG_SIG_FULL: boolean = (() => { try { const v = (process?.env?.VAVOO_LOG_SIG_FULL || '').toLowerCase(); if (['0', 'false', 'off'].includes(v)) return false; if (['1', 'true', 'on'].includes(v)) return true; return true; } catch { return true; } })();
function maskSig(sig: string, keepStart = 12, keepEnd = 6): string { try { if (!sig) return ''; const len = sig.length; const head = sig.slice(0, Math.min(keepStart, len)); const tail = len > keepStart ? sig.slice(Math.max(len - keepEnd, keepStart)) : ''; const hidden = Math.max(0, len - head.length - tail.length); const mask = hidden > 0 ? '*'.repeat(Math.min(hidden, 32)) + (hidden > 32 ? `(+${hidden - 32})` : '') : ''; return `${head}${mask}${tail}`; } catch { return ''; } }

async function getClientIpFromReq(req: Request) {
    try {
        const hdr = req.headers;
        const asStr = (v: string | string[] | undefined) => Array.isArray(v) ? v[0] : (v || '');
        const parseIp = (s: string | undefined) => (s || '').split(',')[0].split(':')[0].trim();
        const stripPort = (s: string) => s.replace(/:\d+$/, '').trim();
        const isPrivate = (ip: string) => /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(ip);
        const pickFirstPublic = (ips: (string | undefined)[]) => ips.find(ip => ip && !isPrivate(ip));

        // 1) X-Forwarded-For: prefer first public entry
        const xffRaw = asStr(hdr['x-forwarded-for']);
        if (xffRaw) {
            const parts = xffRaw.split(',').map(s => parseIp(s)).map(s => s.trim()).filter(Boolean);
            const chosen = pickFirstPublic(parts);
            if (chosen) { vdbg('IP pick via XFF', { chain: parts, chosen }); return chosen; }
        }
        // 2) True-Client-IP / CF-Connecting-IP / X-Real-IP / X-Client-IP
        const tci = stripPort(parseIp(asStr(hdr['true-client-ip'])));
        if (tci && !isPrivate(tci)) { vdbg('IP pick via True-Client-IP', { tci }); return tci; }
        const cfc = stripPort(parseIp(asStr(hdr['cf-connecting-ip'])));
        if (cfc && !isPrivate(cfc)) { vdbg('IP pick via CF-Connecting-IP', { cfc }); return cfc; }
        const xr = stripPort(parseIp(asStr(hdr['x-real-ip'])));
        if (xr && !isPrivate(xr)) { vdbg('IP pick via X-Real-IP', { xr }); return xr; }
        const xci = stripPort(parseIp(asStr(hdr['x-client-ip'])));
        if (xci && !isPrivate(xci)) { vdbg('IP pick via X-Client-IP', { xci }); return xci; }
        // 3) Forwarded: for=
        const fwd = asStr(hdr['forwarded']);
        if (fwd) {
            const m = fwd.match(/for=([^;]+)/i);
            if (m && m[1]) {
                const candidate = stripPort(parseIp(m[1]));
                if (candidate && !isPrivate(candidate)) { vdbg('IP pick via Forwarded', { candidate }); return candidate; }
            }
        }
        // 4) Express provided (requires trust proxy to be set elsewhere)
        const ips = Array.isArray((req as any).ips) ? (req as any).ips : [];
        if (ips.length) {
            const chosen = pickFirstPublic(ips);
            if (chosen) { vdbg('IP pick via req.ips', { ips, chosen }); return chosen; }
        }
        const ra = (req as any).ip || req.socket?.remoteAddress || req.connection?.remoteAddress;
        if (ra) {
            const v = stripPort(String(ra));
            vdbg('IP pick via remoteAddress/ip (fallback)', { v });
            return v.replace(/^\[|\]$/g, '');
        }
    } catch (e) { try { vdbg('IP detect error', String(e)); } catch { } }
    return null;
}

async function resolveVavooCleanUrl(vavooPlayUrl: string, clientIp: string | null): Promise<{ url: string; headers: Record<string, string> } | null> {
    try {
        if (!vavooPlayUrl || !vavooPlayUrl.includes('vavoo.to')) return null;
        // No cache: always resolve per request using the requester IP
        const startedAt = Date.now();
        vdbg('Clean resolve START', { url: vavooPlayUrl.substring(0, 120), ip: clientIp || '(none)' });

        const controller = new AbortController();
        const to = setTimeout(() => {
            vdbg('Ping timeout -> aborting request');
            controller.abort();
        }, 12000);
        const pingBody = {
            token: 'tosFwQCJMS8qrW_AjLoHPQ41646J5dRNha6ZWHnijoYQQQoADQoXYSo7ki7O5-CsgN4CH0uRk6EEoJ0728ar9scCRQW3ZkbfrPfeCXW2VgopSW2FWDqPOoVYIuVPAOnXCZ5g',
            reason: 'app-blur',
            locale: 'de',
            theme: 'dark',
            metadata: {
                device: { type: 'Handset', brand: 'google', model: 'Pixel', name: 'sdk_gphone64_arm64', uniqueId: 'd10e5d99ab665233' },
                os: { name: 'android', version: '13', abis: ['arm64-v8a', 'armeabi-v7a', 'armeabi'], host: 'android' },
                app: { platform: 'android', version: '3.1.21', buildId: '289515000', engine: 'hbc85', signatures: ['6e8a975e3cbf07d5de823a760d4c2547f86c1403105020adee5de67ac510999e'], installer: 'app.revanced.manager.flutter' },
                version: { package: 'tv.vavoo.app', binary: '3.1.21', js: '3.1.21' }
            },
            ipLocation: (clientIp && (!VAVOO_FORCE_SERVER_IP || VAVOO_SET_IPLOCATION_ONLY)) ? clientIp : '',
            playerActive: false,
            playDuration: 0,
            devMode: false,
            hasAddon: true,
            castConnected: false,
            package: 'tv.vavoo.app',
            version: '3.1.21',
            process: 'app',
            firstAppStart: Date.now(),
            lastAppStart: Date.now(),
            adblockEnabled: true,
            proxy: { supported: ['ss', 'openvpn'], engine: 'ss', ssVersion: 1, enabled: true, autoServer: true, id: 'de-fra' },
            iap: { supported: false }
        } as any;
        const pingHeaders: Record<string, string> = { 'user-agent': 'okhttp/4.11.0', 'accept': 'application/json', 'content-type': 'application/json; charset=utf-8', 'accept-encoding': 'gzip' };
        if (clientIp && !VAVOO_FORCE_SERVER_IP) {
            pingHeaders['x-forwarded-for'] = clientIp;
            pingHeaders['x-real-ip'] = clientIp;
            pingHeaders['cf-connecting-ip'] = clientIp;
            // Extra standard/proxy headers to propagate client IP without tampering tokens
            pingHeaders['forwarded'] = `for=${clientIp}`; // RFC 7239
            pingHeaders['true-client-ip'] = clientIp;     // Some CDNs
            pingHeaders['x-client-ip'] = clientIp;        // Legacy
            vdbg('Ping will forward client IP', { xff: clientIp, ipLocation: pingBody.ipLocation });
        } else {
            if (clientIp && VAVOO_SET_IPLOCATION_ONLY) {
                vdbg('Ping ipLocation-only mode: set ipLocation to observed client IP, but using SERVER IP for transport (no forwarding headers).', { observedClientIp: clientIp });
            } else if (clientIp) {
                vdbg('Ping forced to use SERVER IP (no forwarding headers). Observed client IP present but NOT used.', { observedClientIp: clientIp });
            } else {
                vdbg('Ping will use SERVER IP (no client IP observed)');
            }
        }
        vdbg('Ping POST https://www.vavoo.tv/api/app/ping', { ipLocation: pingBody.ipLocation });
        const pingRes = await fetch('https://www.vavoo.tv/api/app/ping', {
            method: 'POST',
            headers: pingHeaders,
            body: JSON.stringify(pingBody),
            signal: controller.signal
        } as any);
        clearTimeout(to);
        vdbg('Ping response', { status: pingRes.status, ok: pingRes.ok, tookMs: Date.now() - startedAt });
        if (!pingRes.ok) {
            let text = '';
            try { text = await pingRes.text(); } catch { }
            vdbg('Ping NOT OK, body snippet:', text.substring(0, 300));
            return null;
        }
        const pingJson = await pingRes.json();
        let addonSig = pingJson?.addonSig as string;
        if (!addonSig) {
            vdbg('Ping OK but addonSig missing. Payload keys:', Object.keys(pingJson || {}));
            return null;
        }
        vdbg('Ping OK, addonSig len:', String(addonSig).length);
        // Show signature in logs (full by default unless disabled)
        const sigPreview = VAVOO_LOG_SIG_FULL ? String(addonSig) : maskSig(String(addonSig));
        vdbg('Ping OK, addonSig preview:', sigPreview);
        // Decode and REWRITE addonSig: replace ips with client IP, then re-encode (per user request)
        try {
            const decoded = Buffer.from(String(addonSig), 'base64').toString('utf8');
            vdbg('addonSig base64 decoded (truncated):', decoded.substring(0, 500));
            let sigObj: any = null;
            try { sigObj = JSON.parse(decoded); } catch { }
            if (sigObj) {
                let dataObj: any = {};
                try { dataObj = JSON.parse(sigObj?.data || '{}'); } catch { }
                const currentIps = Array.isArray(dataObj.ips) ? dataObj.ips : [];
                vdbg('addonSig.data ips (before):', currentIps);
                if (clientIp) {
                    // Rewrite IPs to prioritize the observed client IP
                    const newIps = [clientIp, ...currentIps.filter((x: any) => x && x !== clientIp)];
                    dataObj.ips = newIps;
                    if (typeof dataObj.ip === 'string') dataObj.ip = clientIp;
                    try {
                        sigObj.data = JSON.stringify(dataObj);
                        const reencoded = Buffer.from(JSON.stringify(sigObj), 'utf8').toString('base64');
                        vdbg('addonSig REWRITTEN with client IP', { oldLen: String(addonSig).length, newLen: String(reencoded).length });
                        vdbg('addonSig.data ips (after):', newIps);
                        addonSig = reencoded;
                    } catch (e) {
                        vdbg('addonSig rewrite failed, will use original signature', String(e));
                    }
                } else {
                    vdbg('No client IP observed, addonSig not rewritten');
                }
            }
        } catch { }

        const controller2 = new AbortController();
        const to2 = setTimeout(() => {
            vdbg('Resolve timeout -> aborting request');
            controller2.abort();
        }, 12000);
        const resolveHeaders: Record<string, string> = { 'user-agent': 'MediaHubMX/2', 'accept': 'application/json', 'content-type': 'application/json; charset=utf-8', 'accept-encoding': 'gzip', 'mediahubmx-signature': addonSig };
        if (clientIp && !VAVOO_FORCE_SERVER_IP) {
            resolveHeaders['x-forwarded-for'] = clientIp;
            resolveHeaders['x-real-ip'] = clientIp;
            resolveHeaders['cf-connecting-ip'] = clientIp;
            // Extra standard/proxy headers to propagate client IP without tampering tokens
            resolveHeaders['forwarded'] = `for=${clientIp}`; // RFC 7239
            resolveHeaders['true-client-ip'] = clientIp;     // Some CDNs
            resolveHeaders['x-client-ip'] = clientIp;        // Legacy
            vdbg('Resolve will forward client IP', { xff: clientIp, addonSigLen: String(addonSig).length });
        } else {
            if (clientIp) {
                vdbg('Resolve forced to use SERVER IP (no forwarding headers added). Observed client IP present but NOT used.', { addonSigLen: String(addonSig).length, observedClientIp: clientIp });
            } else {
                vdbg('Resolve will use SERVER IP (no client IP observed)', { addonSigLen: String(addonSig).length });
            }
        }
        // Log the signature being sent to resolve (masked by default)
        vdbg('Resolve using signature:', VAVOO_LOG_SIG_FULL ? String(addonSig) : maskSig(String(addonSig)));
        vdbg('Resolve POST https://vavoo.to/mediahubmx-resolve.json', { url: vavooPlayUrl.substring(0, 120), headers: Object.keys(resolveHeaders) });
        const resolveRes = await fetch('https://vavoo.to/mediahubmx-resolve.json', {
            method: 'POST',
            headers: resolveHeaders,
            body: JSON.stringify({ language: 'de', region: 'AT', url: vavooPlayUrl, clientVersion: '3.1.21' }),
            signal: controller2.signal
        } as any);
        clearTimeout(to2);
        vdbg('Resolve response', { status: resolveRes.status, ok: resolveRes.ok, tookMs: Date.now() - startedAt });
        if (!resolveRes.ok) {
            let text = '';
            try { text = await resolveRes.text(); } catch { }
            vdbg('Resolve NOT OK, body snippet:', text.substring(0, 300));
            return null;
        }
        const resolveJson = await resolveRes.json();
        let resolved: string | null = null;
        if (Array.isArray(resolveJson) && resolveJson.length && resolveJson[0]?.url) resolved = String(resolveJson[0].url);
        else if (resolveJson && typeof resolveJson === 'object' && resolveJson.url) resolved = String(resolveJson.url);
        if (!resolved) {
            vdbg('Resolve OK but no url field in JSON. Shape:', Array.isArray(resolveJson) ? 'array' : typeof resolveJson);
            return null;
        }
        vdbg('Clean resolve SUCCESS', { url: resolved.substring(0, 200) });
        return { url: resolved, headers: { 'User-Agent': DEFAULT_VAVOO_UA, 'Referer': 'https://vavoo.to/' } };
    } catch (e) {
        const msg = (e as any)?.message || String(e);
        vdbg('Clean resolve ERROR:', msg);
        console.error('[VAVOO] Clean resolve failed:', msg);
        return null;
    }
}

// Global runtime configuration cache (was referenced below)
const configCache: AddonConfig = {};

// === CACHE: Per-request Vavoo clean link (per client_ip + link) ===

// Helper: compute Europe/Rome interpretation for eventStart even if timezone is missing
// ================= MANIFEST BASE (restored) =================
const baseManifest: Manifest = {
    id: "org.iceblinker.streamvix",
    version: "7.16.23",
    name: "StreamViX Personal",
    description: "StreamViX addon con VixSRC (Solo Movies/Series)",
    background: "https://raw.githubusercontent.com/qwertyuiop8899/StreamViX/refs/heads/main/public/backround.png",
    types: ["movie", "series"],
    idPrefixes: ["tt", "tmdb"],
    catalogs: [
    ],
    resources: ["stream"],
    behaviorHints: { configurable: true },
    config: [
        { key: "tmdbApiKey", title: "TMDB API Key", type: "text" },
        { key: "mediaFlowProxyUrl", title: "MediaFlow Proxy URL", type: "text" },
        { key: "mediaFlowProxyPassword", title: "MediaFlow Proxy Password", type: "text" },
        // { key: "enableMpd", title: "Enable MPD Streams", type: "checkbox" },
        { key: "disableVixsrc", title: "Disable VixSrc", type: "checkbox" },

        // UI helper toggles (not used directly server-side but drive dynamic form logic)
        { key: "personalTmdbKey", title: "TMDB API KEY Personale", type: "checkbox" },
        { key: "mediaflowMaster", title: "MediaflowProxy", type: "checkbox", default: false },
        { key: "vixProxy", title: "Use MediaFlow Proxy", type: "checkbox", default: false },
        { key: "vixDirect", title: "Show Direct Links (No Proxy)", type: "checkbox", default: true },

    ]
};

// Load custom configuration if available
function loadCustomConfig(): Manifest {
    try {
        const configPath = path.resolve(process.cwd(), 'addon-config.json');

        if (fs.existsSync(configPath)) {
            const customConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));

            return {
                ...baseManifest,
                id: customConfig.addonId || baseManifest.id,
                name: customConfig.addonName || baseManifest.name,
                description: customConfig.addonDescription || baseManifest.description,
                version: customConfig.addonVersion || baseManifest.version,
                logo: customConfig.addonLogo || baseManifest.logo,
                icon: customConfig.addonLogo || baseManifest.icon,
                background: baseManifest.background
            };
        }
    } catch (error) {
        console.error('Error loading custom configuration:', error);
    }

    return baseManifest;
}

// Funzione per parsare la configurazione dall'URL
function parseConfigFromArgs(args: any): AddonConfig {
    const config: AddonConfig = {};

    // Se non ci sono args o sono vuoti, ritorna configurazione vuota
    if (!args || args === '' || args === 'undefined' || args === 'null') {
        debugLog('No configuration provided, using defaults');
        return config;
    }

    // Se la configurazione Ã¨ giÃ  un oggetto, usala direttamente
    if (typeof args === 'object' && args !== null) {
        debugLog('Configuration provided as object');
        return args;
    }

    if (typeof args === 'string') {
        debugLog(`Configuration string: ${args.substring(0, 50)}... (length: ${args.length})`);

        // PASSO 1: Prova JSON diretto
        try {
            const parsed = JSON.parse(args);
            debugLog('Configuration parsed as direct JSON');
            return parsed;
        } catch (error) {
            debugLog('Not direct JSON, trying other methods');
        }

        // PASSO 2: Gestione URL encoded
        let decodedArgs = args;
        if (args.includes('%')) {
            try {
                decodedArgs = decodeURIComponent(args);
                debugLog('URL-decoded configuration');

                // Prova JSON dopo URL decode
                try {
                    const parsed = JSON.parse(decodedArgs);
                    debugLog('Configuration parsed from URL-decoded JSON');
                    return parsed;
                } catch (innerError) {
                    debugLog('URL-decoded content is not valid JSON');
                }
            } catch (error) {
                debugLog('URL decoding failed');
            }
        }

        // PASSO 3: Gestione Base64
        if (decodedArgs.startsWith('eyJ') || /^[A-Za-z0-9+\/=]+$/.test(decodedArgs)) {
            try {
                // Fix per caratteri = che potrebbero essere URL encoded
                const base64Fixed = decodedArgs
                    .replace(/%3D/g, '=')
                    .replace(/=+$/, ''); // Rimuove eventuali = alla fine

                // Assicura che la lunghezza sia multipla di 4 aggiungendo = se necessario
                let paddedBase64 = base64Fixed;
                while (paddedBase64.length % 4 !== 0) {
                    paddedBase64 += '=';
                }

                debugLog(`Trying base64 decode: ${paddedBase64.substring(0, 20)}...`);
                const decoded = Buffer.from(paddedBase64, 'base64').toString('utf-8');
                debugLog(`Base64 decoded result: ${decoded.substring(0, 50)}...`);

                if (decoded.includes('{') && decoded.includes('}')) {
                    try {
                        const parsed = JSON.parse(decoded);
                        debugLog('Configuration parsed from Base64');
                        return parsed;
                    } catch (jsonError) {
                        debugLog('Base64 content is not valid JSON');

                        // Prova a estrarre JSON dalla stringa decodificata
                        const jsonMatch = decoded.match(/({.*})/);
                        if (jsonMatch && jsonMatch[1]) {
                            try {
                                const extractedJson = jsonMatch[1];
                                const parsed = JSON.parse(extractedJson);
                                debugLog('Extracted JSON from Base64 decoded string');
                                return parsed;
                            } catch (extractError) {
                                debugLog('Extracted JSON parsing failed');
                            }
                        }
                    }
                }
            } catch (error) {
                debugLog('Base64 decoding failed');
            }
        }

        debugLog('All parsing methods failed, using default configuration');
    }

    return config;
}



// âœ… DICHIARAZIONE delle variabili globali del builder
let globalBuilder: any;
let globalAddonInterface: any;
let globalRouter: any;
let lastDisableLiveTvFlag: boolean | undefined;
let staticBaseChannels: any[] = [];
let tvChannels: any[] = [];
let domains: any = [];
let epgConfig: any = { enabled: false };
let epgManager: EPGManager | null = null;

// === Lightweight watcher state for static tv_channels.json reload ===
let _staticFilePath: string | null = null;
let _staticFileLastMtime = 0;
let _staticFileLastHash = '';
function _computeHash(buf: Buffer): string { try { return crypto.createHash('md5').update(buf).digest('hex'); } catch { return ''; } }
function _resolveStaticPath(): string {
    if (_staticFilePath && fs.existsSync(_staticFilePath)) return _staticFilePath;
    const candidates = [
        path.join(__dirname, '..', 'config', 'tv_channels.json'),
        path.join(process.cwd(), 'config', 'tv_channels.json'),
        path.join(__dirname, 'config', 'tv_channels.json')
    ];
    for (const c of candidates) { if (fs.existsSync(c)) { _staticFilePath = c; return c; } }
    return candidates[0];
}
function _loadStaticChannelsIfChanged(force = false) {
    try {
        const p = _resolveStaticPath();
        if (!fs.existsSync(p)) return;
        const st = fs.statSync(p);
        const mtime = st.mtimeMs;
        if (!force && mtime === _staticFileLastMtime) return; // quick check
        const raw = fs.readFileSync(p);
        const h = _computeHash(raw);
        if (!force && mtime === _staticFileLastMtime && h === _staticFileLastHash) return;
        const parsed = JSON.parse(raw.toString('utf-8'));
        if (!Array.isArray(parsed)) return;
        staticBaseChannels = parsed;
        _staticFileLastMtime = mtime;
        _staticFileLastHash = h;
        // Count pdUrlF present
        let pdCount = 0; let total = parsed.length;
        for (const c of parsed) if (c && c.pdUrlF) pdCount++;
        console.log(`[TV][RELOAD] staticBaseChannels reloaded: total=${total} pdUrlF=${pdCount} mtime=${new Date(mtime).toISOString()} hash=${h.slice(0, 12)}`);
    } catch (e) {
        console.warn('[TV][RELOAD] errore reload static tv_channels:', (e as any)?.message || e);
    }
}
// WATCH UNIFICATO: controlla sia static (tv_channels.json) che dynamic (dynamic_channels.json)
//   - Intervallo configurabile con WATCH_INTERVAL_MS (fallback: TV_STATIC_WATCH_INTERVAL_MS / DYNAMIC_WATCH_INTERVAL_MS / 300000)
//   - Static: usa _loadStaticChannelsIfChanged (già fa hash/mtime e log solo se cambia)
//   - Dynamic: calcola mtime+hash e se cambia invalida+reload
(() => {
    try {
        const intervalMs = parseInt(process.env.WATCH_INTERVAL_MS || process.env.TV_STATIC_WATCH_INTERVAL_MS || process.env.DYNAMIC_WATCH_INTERVAL_MS || '300000', 10); // default 5m
        let lastDynMtime = 0; let lastDynHash = '';
        async function checkDynamicOnce() {
            try {
                const p = getDynamicFilePath();
                if (!p || !fs.existsSync(p)) return;
                const st = fs.statSync(p);
                const raw = fs.readFileSync(p);
                const h = _computeHash(raw);
                if (st.mtimeMs !== lastDynMtime || h !== lastDynHash) {
                    const oldShort = lastDynHash.slice(0, 8);
                    lastDynMtime = st.mtimeMs; lastDynHash = h;
                    invalidateDynamicChannels();
                    const channels = await loadDynamicChannels(true);
                    console.log(`[WATCH][DYN] reload (changed) oldHash=${oldShort} newHash=${h.slice(0, 8)} count=${channels.length}`);
                }
            } catch (e) {
                console.warn('[WATCH][DYN] errore controllo dynamic:', (e as any)?.message || e);
            }
        }
        function loop() {
            try {
                _loadStaticChannelsIfChanged(false);
                checkDynamicOnce();
            } finally {
                // next tick gestito da setInterval
            }
        }
        // primo giro: forziamo static + dynamic
        setTimeout(() => { _loadStaticChannelsIfChanged(true); checkDynamicOnce(); }, 1500);
        setInterval(loop, Math.max(60000, intervalMs));
        console.log(`[WATCH] unificato attivo ogni ${Math.max(60000, intervalMs)}ms (default 5m)`);
    } catch (e) {
        console.log('[WATCH] init failed', (e as any)?.message || e);
    }
})();

// (RIMOSSO) watcher dinamico separato (ora unificato sopra)
// === STREAMED playlist enrichment (spawns external python script) ===
(() => {
    try {
        // Auto-enable STREAMED enrichment if the user hasn't explicitly set STREAMED_ENABLE.
        // Rationale: we want the enrichment active by default (was originally introduced for a test phase).
        let enableRaw = (process.env.STREAMED_ENABLE || '').toString().toLowerCase();
        if (!enableRaw) {
            // default ON in absence of explicit value so that the enrichment always runs unless explicitly disabled
            enableRaw = '1';
            process.env.STREAMED_ENABLE = '1';
            console.log('[STREAMED][INIT] abilitazione automatica');
        }
        const enable = enableRaw;
        if (!['1', 'true', 'on', 'yes'].includes(enable)) return;
        const intervalMs = Math.max(30000, parseInt(process.env.STREAMED_POLL_INTERVAL_MS || '120000', 10)); // default 120s (allineato a RBTV)
        const pythonBin = process.env.PYTHON_BIN || 'python';
        const scriptPath = path.join(__dirname, '..', 'streamed_channels.py');
        if (!fs.existsSync(scriptPath)) { console.log('[STREAMED][INIT] script non trovato', scriptPath); return; }
        function runOnce(tag: string) {
            const env: any = { ...process.env };
            // Propaga percorso dynamic se usato
            try { env.DYNAMIC_FILE = getDynamicFilePath(); } catch { }
            const t0 = Date.now();
            const child = spawn(pythonBin, [scriptPath], { env });
            let out = ''; let err = '';
            child.stdout.on('data', d => { out += d.toString(); });
            child.stderr.on('data', d => { err += d.toString(); });
            child.on('close', code => {
                const ms = Date.now() - t0;
                if (out.trim()) out.split(/\r?\n/).forEach(l => console.log('[STREAMED][OUT]', l));
                if (err.trim()) err.split(/\r?\n/).forEach(l => console.warn('[STREAMED][ERR]', l));
                console.log(`[STREAMED][RUN] done code=${code} ms=${ms}`);
            });
        }
        // Force headers + force mode for initial test run (Bologna vs Genoa) unless user explicitly disables
        const initialEnv = { ...process.env };
        if (!initialEnv.STREAMED_FORCE) initialEnv.STREAMED_FORCE = '1';
        if (!initialEnv.STREAMED_PROPAGATE_HEADERS) initialEnv.STREAMED_PROPAGATE_HEADERS = '1';
        // Kick an immediate run (slight delay to allow Live.py generation) with forced env
        setTimeout(() => {
            const t0 = Date.now();
            try { initialEnv.DYNAMIC_FILE = getDynamicFilePath(); } catch { }
            const child = spawn(pythonBin, [scriptPath], { env: initialEnv });
            let out = ''; let err = '';
            child.stdout.on('data', (d: any) => out += d.toString());
            child.stderr.on('data', (d: any) => err += d.toString());
            child.on('close', (code: any) => {
                const ms = Date.now() - t0;
                if (out.trim()) out.split(/\r?\n/).forEach(l => console.log('[STREAMED][OUT][INIT]', l));
                if (err.trim()) err.split(/\r?\n/).forEach(l => console.warn('[STREAMED][ERR][INIT]', l));
                console.log(`[STREAMED][RUN][INIT] done code=${code} ms=${ms}`);
            });
        }, 5000);
        setInterval(() => runOnce('loop'), intervalMs);
        console.log('[STREAMED][INIT] abilitato poll ogni', intervalMs, 'ms');
    } catch (e) {
        console.log('[STREAMED][INIT][ERR]', (e as any)?.message || e);
    }
})();

// === RBTV (RB77) playlist enrichment ===
(() => {
    try {
        let enableRaw = (process.env.RBTV_ENABLE || '').toString().toLowerCase();
        if (!enableRaw) {
            enableRaw = '1';
            process.env.RBTV_ENABLE = '1';
            console.log('[RBTV][INIT] abilitazione automatica');
        }
        if (!['1', 'true', 'on', 'yes'].includes(enableRaw)) return;
        const pythonBin = process.env.PYTHON_BIN || 'python';
        const scriptPath = path.join(__dirname, '..', 'rbtv_streams.py');
        if (!fs.existsSync(scriptPath)) { console.log('[RBTV][INIT] script non trovato', scriptPath); return; }
        const intervalMs = Math.max(60000, parseInt(process.env.RBTV_POLL_INTERVAL_MS || '120000', 10)); // default 120s
        function runOnce(tag: string) {
            const env: any = { ...process.env };
            try { env.DYNAMIC_FILE = getDynamicFilePath(); } catch { }
            const t0 = Date.now();
            const child = spawn(pythonBin, [scriptPath], { env });
            let out = ''; let err = '';
            child.stdout.on('data', d => out += d.toString());
            child.stderr.on('data', d => err += d.toString());
            child.on('close', code => {
                const ms = Date.now() - t0;
                if (out.trim()) out.split(/\r?\n/).forEach(l => console.log('[RBTV][OUT]', l));
                if (err.trim()) err.split(/\r?\n/).forEach(l => console.warn('[RBTV][ERR]', l));
                console.log(`[RBTV][RUN] done code=${code} ms=${ms}`);
            });
        }
        // Primo giro forzato (RBTV_FORCE=1) ritardato per lasciare generare Live.py, simile a STREAMED_FORCE
        setTimeout(() => {
            try {
                const initialEnv: any = { ...process.env };
                if (!initialEnv.RBTV_FORCE) initialEnv.RBTV_FORCE = '1'; // forza discovery iniziale
                try { initialEnv.DYNAMIC_FILE = getDynamicFilePath(); } catch { }
                const t0 = Date.now();
                const child = spawn(pythonBin, [scriptPath], { env: initialEnv });
                let out = ''; let err = '';
                child.stdout.on('data', (d: any) => out += d.toString());
                child.stderr.on('data', (d: any) => err += d.toString());
                child.on('close', (code: any) => {
                    const ms = Date.now() - t0;
                    if (out.trim()) out.split(/\r?\n/).forEach(l => console.log('[RBTV][OUT][INIT]', l));
                    if (err.trim()) err.split(/\r?\n/).forEach(l => console.warn('[RBTV][ERR][INIT]', l));
                    console.log(`[RBTV][RUN][INIT] done code=${code} ms=${ms}`);
                });
            } catch (e) {
                console.log('[RBTV][INIT][FORCE][ERR]', (e as any)?.message || e);
            }
        }, 7000);
        setInterval(() => runOnce('loop'), intervalMs);
        console.log('[RBTV][INIT] poll ogni', intervalMs, 'ms');
    } catch (e) {
        console.log('[RBTV][INIT][ERR]', (e as any)?.message || e);
    }
})();

// === SPSO (SportsOnline) playlist enrichment ===
(() => {
    try {
        let enableRaw = (process.env.SPSO_ENABLE || '').toString().toLowerCase();
        if (!enableRaw) {
            enableRaw = '1';
            process.env.SPSO_ENABLE = '1';
            console.log('[SPSO][INIT] abilitazione automatica');
        }
        if (!['1', 'true', 'on', 'yes'].includes(enableRaw)) return;
        const pythonBin = process.env.PYTHON_BIN || 'python3';
        const scriptPath = path.join(__dirname, '..', 'spso_streams.py');
        if (!fs.existsSync(scriptPath)) { console.log('[SPSO][INIT] script non trovato', scriptPath); return; }
        const intervalMs = Math.max(60000, parseInt(process.env.SPSO_POLL_INTERVAL_MS || '120000', 10));
        function runOnce(tag: string) {
            const env: any = { ...process.env };
            try { env.DYNAMIC_FILE = getDynamicFilePath(); } catch { }
            const t0 = Date.now();
            const child = spawn(pythonBin, [scriptPath], { env });
            let out = ''; let err = '';
            child.stdout.on('data', d => out += d.toString());
            child.stderr.on('data', d => err += d.toString());
            child.on('close', code => {
                const ms = Date.now() - t0;
                if (out.trim()) out.split(/\r?\n/).forEach(l => console.log('[SPSO][OUT]', l));
                if (err.trim()) err.split(/\r?\n/).forEach(l => console.warn('[SPSO][ERR]', l));
                console.log(`[SPSO][RUN] done code=${code} ms=${ms}`);
            });
        }
        setTimeout(() => {
            try {
                const initialEnv: any = { ...process.env };
                if (!initialEnv.SPSO_FORCE) initialEnv.SPSO_FORCE = '1';
                try { initialEnv.DYNAMIC_FILE = getDynamicFilePath(); } catch { }
                const t0 = Date.now();
                const child = spawn(pythonBin, [scriptPath], { env: initialEnv });
                let out = ''; let err = '';
                child.stdout.on('data', d => out += d.toString());
                child.stderr.on('data', d => err += d.toString());
                child.on('close', code => {
                    const ms = Date.now() - t0;
                    if (out.trim()) out.split(/\r?\n/).forEach(l => console.log('[SPSO][OUT][INIT]', l));
                    if (err.trim()) err.split(/\r?\n/).forEach(l => console.warn('[SPSO][ERR][INIT]', l));
                    console.log(`[SPSO][RUN][INIT] done code=${code} ms=${ms}`);
                });
            } catch (e) {
                console.log('[SPSO][INIT][FORCE][ERR]', (e as any)?.message || e);
            }
        }, 9000); // dopo RBTV per non sovrapporsi all'iniziale RBTV run
        setInterval(() => runOnce('loop'), intervalMs);
        console.log('[SPSO][INIT] poll ogni', intervalMs, 'ms');
    } catch (e) {
        console.log('[SPSO][INIT][ERR]', (e as any)?.message || e);
    }
})();

// (RIMOSSO) Adaptive windows: sostituito da watcher semplice costante.

// =====================================
// [P🐽D] STARTUP DIAGNOSTICS (container parity)
// Attivabile con env: DIAG_PD=1 (default ON per ora salvo DIAG_PD=0)
// Stampa informazioni su:
//  - Presenza & hash di pig_channels.py
//  - Presenza & hash di config/tv_channels.json
//  - Presenza, size, mtime del dynamic_channels.json selezionato (via getDynamicFilePath)
//  - Conteggio rapida occorrenze label "[P🐽D]" nel dynamic_channels.json (per confermare injection)
// =====================================
(() => {
    try {
        const envVal = (process?.env?.DIAG_PD || '1').toString().toLowerCase();
        if (['0', 'false', 'off', 'no'].includes(envVal)) {
            return; // diagnostics disabilitata
        }
        const root = path.join(__dirname, '..');
        const fileInfo = (rel: string) => {
            const p = path.join(root, rel);
            if (!fs.existsSync(p)) return { path: p, exists: false, size: 0, mtime: 0, md5: '' };
            const st = fs.statSync(p);
            let md5 = '';
            try { md5 = crypto.createHash('md5').update(fs.readFileSync(p)).digest('hex'); } catch { }
            return { path: p, exists: true, size: st.size, mtime: st.mtimeMs, md5 };
        };
        const pig = fileInfo('pig_channels.py');
        const tvc = fileInfo('config/tv_channels.json');
        // dynamic file path discovery (may live in /tmp or config/)
        let dynPath = '';
        let dynStats: any = { path: '', exists: false, size: 0, mtime: 0, md5: '', pdStreams: 0 };
        try {
            dynPath = getDynamicFilePath();
            if (dynPath && fs.existsSync(dynPath)) {
                const st = fs.statSync(dynPath);
                let md5 = '';
                try { md5 = crypto.createHash('md5').update(fs.readFileSync(dynPath)).digest('hex'); } catch { }
                // Quick scan for label occurrences (keep light: don't parse JSON if huge)
                let pdStreams = 0;
                try {
                    const raw = fs.readFileSync(dynPath, 'utf-8');
                    // Count occurrences of string "[P🐽D]" (label start) to confirm injection; fallback to "[P" if pig emoji missing fonts
                    const re = /\[P🐽D\]/g; // literal match
                    const reAlt = /\[P.D\]/g; // extremely defensive (unlikely)
                    const matches = raw.match(re);
                    pdStreams = matches ? matches.length : 0;
                    if (!pdStreams) {
                        const alt = raw.match(reAlt);
                        if (alt) pdStreams = alt.length;
                    }
                } catch { }
                dynStats = { path: dynPath, exists: true, size: st.size, mtime: st.mtimeMs, md5, pdStreams };
            } else {
                dynStats = { path: dynPath || '(empty)', exists: false, size: 0, mtime: 0, md5: '', pdStreams: 0 };
            }
        } catch (e) {
            dynStats = { path: dynPath || '(error)', exists: false, size: 0, mtime: 0, md5: '', err: String(e), pdStreams: 0 };
        }
        const fmtTime = (ms: number) => {
            if (!ms) return 0;
            try { return new Date(ms).toISOString(); } catch { return ms; }
        };
        console.log('[P🐽D][DIAG] pig_channels.py', { exists: pig.exists, size: pig.size, mtime: fmtTime(pig.mtime), md5: pig.md5.slice(0, 12) });
        console.log('[P🐽D][DIAG] tv_channels.json', { exists: tvc.exists, size: tvc.size, mtime: fmtTime(tvc.mtime), md5: tvc.md5.slice(0, 12) });
        console.log('[P🐽D][DIAG] dynamic_channels.json', { path: dynStats.path, exists: dynStats.exists, size: dynStats.size, mtime: fmtTime(dynStats.mtime), md5: (dynStats.md5 || '').slice(0, 12), pdLabelCount: dynStats.pdStreams });
        if (!dynStats.exists) {
            console.warn('[P🐽D][DIAG] dynamic_channels.json NON TROVATO al bootstrap – Live.py o pig_channels.py non ancora eseguiti nel container?');
        } else if (dynStats.exists && dynStats.pdStreams === 0) {
            console.warn('[P🐽D][DIAG] dynamic_channels.json presente ma CONTATORE label [P🐽D] = 0 – possibili cause: pig_channels non eseguito / label diversa / build cache vecchia.');
        }
    } catch (e) {
        try { console.error('[P🐽D][DIAG] Errore diagnostics startup:', e); } catch { }
    }
})();
// =====================================



const vavooCache: VavooCache = {
    timestamp: 0,
    links: new Map<string, string | string[]>(),
    updating: false
};

// Path del file di cache per Vavoo
const vavooCachePath = path.join(__dirname, '../cache/vavoo_cache.json');

// Se la cache non esiste, genera automaticamente
if (!fs.existsSync(vavooCachePath)) {
    console.warn('⚠️ [VAVOO] Cache non trovata, provo a generarla automaticamente...');
    try {
        const { execSync } = require('child_process');
        const pythonBin = process.env.PYTHON_BIN || 'python3';
        execSync(`${pythonBin} vavoo_resolver.py --build-cache`, { cwd: path.join(__dirname, '..') });
        console.log('✅ [VAVOO] Cache generata automaticamente!');
    } catch (err) {
        console.error('❌ [VAVOO] Errore nella generazione automatica della cache:', err);
    }
}

// Funzione per caricare la cache Vavoo dal file
function loadVavooCache(): void {
    try {
        if (fs.existsSync(vavooCachePath)) {
            const rawCache = fs.readFileSync(vavooCachePath, 'utf-8');
            // RIMOSSO: console.log('🔧 [VAVOO] RAW vavoo_cache.json:', rawCache);
            const cacheData = JSON.parse(rawCache);
            vavooCache.timestamp = cacheData.timestamp || 0;
            vavooCache.links = new Map(Object.entries(cacheData.links || {}));
            console.log(`📺 Vavoo cache caricata con ${vavooCache.links.size} canali, aggiornata il: ${new Date(vavooCache.timestamp).toLocaleString()}`);
            console.log('🔧 [VAVOO] DEBUG - Cache caricata all\'avvio:', vavooCache.links.size, 'canali');
            console.log('🔧 [VAVOO] DEBUG - Path cache:', vavooCachePath);
            // RIMOSSO: stampa dettagliata del contenuto della cache
        } else {
            console.log(`📺 File cache Vavoo non trovato, verrà creato al primo aggiornamento`);
        }
    } catch (error) {
        console.error('❌ Errore nel caricamento della cache Vavoo:', error);
    }
}

// Funzione per salvare la cache Vavoo su file
function saveVavooCache(): void {
    try {
        // Assicurati che la directory cache esista
        const cacheDir = path.dirname(vavooCachePath);
        if (!fs.existsSync(cacheDir)) {
            fs.mkdirSync(cacheDir, { recursive: true });
        }

        const cacheData = {
            timestamp: vavooCache.timestamp,
            links: Object.fromEntries(vavooCache.links)
        };

        // Salva prima in un file temporaneo e poi rinomina per evitare file danneggiati
        const tempPath = `${vavooCachePath}.tmp`;
        fs.writeFileSync(tempPath, JSON.stringify(cacheData, null, 2), 'utf-8');

        // Rinomina il file temporaneo nel file finale
        fs.renameSync(tempPath, vavooCachePath);

        console.log(`📺 Vavoo cache salvata con ${vavooCache.links.size} canali, timestamp: ${new Date(vavooCache.timestamp).toLocaleString()}`);
    } catch (error) {
        console.error('❌ Errore nel salvataggio della cache Vavoo:', error);
    }
}

// Funzione per aggiornare la cache Vavoo
async function updateVavooCache(): Promise<boolean> {
    if (vavooCache.updating) {
        console.log(`📺 Aggiornamento Vavoo già in corso, skip`);
        return false;
    }

    vavooCache.updating = true;
    console.log(`📺 Avvio aggiornamento cache Vavoo...`);
    try {
        // PATCH: Prendi TUTTI i canali da Vavoo, senza filtri su tv_channels.json
        const pythonBin = process.env.PYTHON_BIN || 'python3';
        const result = await execFilePromise(pythonBin, [
            path.join(__dirname, '../vavoo_resolver.py'),
            '--dump-channels'
        ], { timeout: 30000 });

        if (result.stdout) {
            try {
                const channels = JSON.parse(result.stdout);
                console.log(`📺 Recuperati ${channels.length} canali da Vavoo (nessun filtro)`);
                const updatedLinks = new Map<string, string>();
                for (const ch of channels) {
                    if (!ch || !ch.name || !ch.links) continue;
                    const first = Array.isArray(ch.links) ? ch.links[0] : ch.links;
                    if (first) updatedLinks.set(String(ch.name), String(first));
                }
                vavooCache.links = updatedLinks;
                vavooCache.timestamp = Date.now();
                saveVavooCache();
                console.log(`📺 Vavoo cache aggiornata: ${vavooCache.links.size} canali salvati`);
            } catch (e) {
                console.error('❌ Errore nel parsing canali Vavoo:', e);
            }
        } else {
            console.warn('⚠️ Nessun output da vavoo_resolver.py --dump-channels');
        }
        return true;
    } catch (error) {
        console.error('❌ Errore aggiornamento cache Vavoo:', error);
        return false;
    } finally {
        vavooCache.updating = false;
    }
}

const vavooAliasIndex = new Map<string, string>();

function normAlias(s: string): string {
    return (s || '')
        .toLowerCase()
        .normalize('NFKD')
        .replace(/[\u0300-\u036f]/g, '') // rimuovi diacritici
        .replace(/[^a-z0-9]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
}

function buildVavooAliasIndex(): void {
    try {
        vavooAliasIndex.clear();
        const source = Array.isArray(staticBaseChannels) && staticBaseChannels.length ? staticBaseChannels : tvChannels;
        for (const ch of (source as any[])) {
            if (!ch) continue;
            const aliases: string[] = Array.isArray(ch.vavooNames) && ch.vavooNames.length ? ch.vavooNames : (ch.name ? [ch.name] : []);
            for (const a of aliases) {
                const key = normAlias(String(a));
                if (!key) continue;
                if (!vavooAliasIndex.has(key)) vavooAliasIndex.set(key, String(a));
            }
        }
        console.log(`🧭 Vavoo alias index built: ${vavooAliasIndex.size} aliases`);
    } catch (e) {
        console.error('❌ Errore build Vavoo alias index:', e);
    }
}

function findBestAliasInTexts(texts: string[]): string | null {
    if (!texts || !texts.length || vavooAliasIndex.size === 0) return null;
    let best: { alias: string; len: number } | null = null;
    for (const raw of texts) {
        if (!raw) continue;
        const t = normAlias(String(raw));
        if (!t) continue;
        for (const [k, original] of vavooAliasIndex.entries()) {
            if (!k) continue;
            // match come parola intera o sottostringa significativa
            // costruisci regex che richiede confini di parola debole
            const pattern = new RegExp(`(?:^| )${k}(?: |$)`);
            if (pattern.test(t)) {
                const L = k.length;
                if (!best || L > best.len) best = { alias: original, len: L };
            }
        }
    }
    return best ? best.alias : null;
}

function resolveFirstVavooUrlForAlias(alias: string): string | null {
    if (!alias || !vavooCache || !vavooCache.links) return null;
    // 1) Prova varianti "Nome .<lettera>"
    try {
        const variantRegex = new RegExp(`^${alias} \\.([a-zA-Z])$`, 'i');
        for (const [key, value] of vavooCache.links.entries()) {
            if (variantRegex.test(key)) {
                const links = Array.isArray(value) ? value : [value];
                if (links.length) return String(links[0]);
            }
        }
        // 2) Prova match normalizzato sulle chiavi
        const aliasNorm = alias.toUpperCase().replace(/\s+/g, ' ').trim();
        for (const [key, value] of vavooCache.links.entries()) {
            const keyNorm = key.toUpperCase().replace(/\s+/g, ' ').trim();
            const rx = new RegExp(`^${aliasNorm} \\.([a-zA-Z])$`, 'i');
            if (rx.test(keyNorm)) {
                const links = Array.isArray(value) ? value : [value];
                if (links.length) return String(links[0]);
            }
        }
        // 3) Fallback chiave esatta
        const exact = vavooCache.links.get(alias) as any;
        if (exact) {
            const links = Array.isArray(exact) ? exact : [exact];
            if (links.length) return String(links[0]);
        }
    } catch (e) {
        console.error('[VAVOO] resolveFirstVavooUrlForAlias error:', e);
    }
    return null;
}

try {
    // Assicurati che le directory di cache esistano
    ensureCacheDirectories();

    staticBaseChannels = JSON.parse(fs.readFileSync(path.join(__dirname, '../config/tv_channels.json'), 'utf-8'));
    tvChannels = [...staticBaseChannels];
    domains = JSON.parse(fs.readFileSync(path.join(__dirname, '../config/domains.json'), 'utf-8'));
    epgConfig = JSON.parse(fs.readFileSync(path.join(__dirname, '../config/epg_config.json'), 'utf-8'));

    console.log(`✅ Loaded ${tvChannels.length} TV channels`);

    // ============ TVTAP INTEGRATION ============

    // Cache per i link TVTap
    interface TVTapCache {
        timestamp: number;
        channels: Map<string, string>;
        updating: boolean;
    }

    const tvtapCache: TVTapCache = {
        timestamp: 0,
        channels: new Map<string, string>(),
        updating: false
    };

    // Path del file di cache per TVTap
    const tvtapCachePath = path.join(__dirname, '../cache/tvtap_cache.json');

    // Funzione per caricare la cache TVTap dal file
    function loadTVTapCache(): void {
        try {
            if (fs.existsSync(tvtapCachePath)) {
                const rawCache = fs.readFileSync(tvtapCachePath, 'utf-8');
                const cacheData = JSON.parse(rawCache);
                tvtapCache.timestamp = cacheData.timestamp || 0;
                tvtapCache.channels = new Map(Object.entries(cacheData.channels || {}));
                console.log(`📺 TVTap cache caricata con ${tvtapCache.channels.size} canali, aggiornata il: ${new Date(tvtapCache.timestamp).toLocaleString()}`);
            } else {
                console.log("📺 File cache TVTap non trovato, verrà creato al primo aggiornamento");
            }
        } catch (error) {
            console.error("❌ Errore nel caricamento cache TVTap:", error);
            tvtapCache.timestamp = 0;
            tvtapCache.channels = new Map();
        }
    }

    // Funzione per aggiornare la cache TVTap
    async function updateTVTapCache(): Promise<boolean> {
        if (tvtapCache.updating) {
            console.log('🔄 TVTap cache già in aggiornamento, salto...');
            return false;
        }

        tvtapCache.updating = true;
        console.log('🔄 Aggiornamento cache TVTap...');

        try {
            const options = {
                timeout: 30000,
                env: {
                    ...process.env,
                    PYTHONPATH: '/usr/local/lib/python3.9/site-packages'
                }
            };

            const pythonBin = process.env.PYTHON_BIN || 'python3';
            const { stdout, stderr } = await execFilePromise(pythonBin, [path.join(__dirname, '../tvtap_resolver.py'), '--build-cache'], options);

            if (stderr) {
                console.error(`[TVTap] Script stderr:`, stderr);
            }

            console.log('✅ Cache TVTap aggiornata con successo');

            // Ricarica la cache aggiornata
            loadTVTapCache();

            return true;
        } catch (error: any) {
            console.error('❌ Errore durante aggiornamento cache TVTap:', error.message || error);
            return false;
        } finally {
            tvtapCache.updating = false;
        }
    }

    // ============ END TVTAP INTEGRATION ============

    // ✅ INIZIALIZZA IL ROUTER GLOBALE SUBITO DOPO IL CARICAMENTO
    console.log('🔧 Initializing global router after loading TV channels...');
    globalBuilder = createBuilder(configCache);
    globalAddonInterface = globalBuilder.getInterface();
    globalRouter = getRouter(globalAddonInterface);
    console.log('✅ Global router initialized successfully');

    // Carica la cache Vavoo
    loadVavooCache();
    // Costruisci indice alias Vavoo
    buildVavooAliasIndex();

    // Dopo il caricamento della cache Vavoo
    if (vavooCache && vavooCache.links) {
        try {
            console.log(`[VAVOO] Cache caricata: ${vavooCache.links.size} canali`);
        } catch (e) {
            console.log('[VAVOO] ERRORE DUMP CACHE:', e);
        }
    }

    // Carica la cache TVTap
    loadTVTapCache();

    // Aggiorna la cache Vavoo in background all'avvio
    setTimeout(() => {
        updateVavooCache().then(success => {
            if (success) {
                console.log(`✅ Cache Vavoo aggiornata con successo all'avvio`);
                // Avvia Live.py subito dopo il successo della cache Vavoo (una volta, non bloccante)
                try {
                    const livePath = path.join(__dirname, '../Live.py');
                    const fs = require('fs');
                    if (fs.existsSync(livePath)) {
                        try {
                            const st = fs.statSync(livePath);
                            console.log('[Live.py][DIAG] path=', livePath, 'size=', st.size, 'mtime=', new Date(st.mtimeMs || st.mtime).toISOString());
                        } catch { }
                        // individua interpreti python disponibili
                        const candidateBins = [process.env.PYTHON_BIN, 'python3', 'python', 'py'].filter(Boolean) as string[];
                        let chosen: string | null = null;
                        for (const b of candidateBins) {
                            try {
                                const { spawnSync } = require('child_process');
                                const r = spawnSync(b, ['-V'], { timeout: 4000 });
                                if (r.status === 0 && String(r.stdout || r.stderr).toLowerCase().includes('python')) {
                                    chosen = b; console.log('[Live.py][DIAG] interpreter ok ->', b, 'version:', (r.stdout || r.stderr).toString().trim());
                                    break;
                                }
                            } catch { }
                        }
                        if (!chosen) {
                            console.warn('[Live.py][DIAG] nessun interprete Python funzionante trovato tra', candidateBins.join(','));
                        }
                        const trySpawn = (py: string) => {
                            try {
                                const child = require('child_process').spawn(py, [livePath], { detached: true, stdio: 'ignore' });
                                child.unref();
                                console.log(`[Live.py] avviato in background con '${py}'`);
                                return true;
                            } catch { return false; }
                        };
                        if (chosen) {
                            if (!trySpawn(chosen)) console.warn('[Live.py][DIAG] spawn fallita con', chosen);
                        } else {
                            if (!trySpawn('python3')) trySpawn('python');
                        }
                    } else {
                        console.log('[Live.py] non trovato, skip');
                    }
                } catch (e) {
                    console.log('[Live.py] errore avvio non bloccante:', (e as any)?.message || e);
                }
            } else {
                console.log(`⚠️ Aggiornamento cache Vavoo fallito all'avvio, verrà ritentato periodicamente`);
            }
        }).catch(error => {
            console.error(`❌ Errore durante l'aggiornamento cache Vavoo all'avvio:`, error);
        });
    }, 2000);

    // Aggiorna la cache TVTap in background all'avvio
    setTimeout(() => {
        updateTVTapCache().then(success => {
            if (success) {
                console.log(`✅ Cache TVTap aggiornata con successo all'avvio`);
            } else {
                console.log(`⚠️ Aggiornamento cache TVTap fallito all'avvio, verrà ritentato periodicamente`);
            }
        }).catch(error => {
            console.error(`❌ Errore durante l'aggiornamento cache TVTap all'avvio:`, error);
        });
    }, 4000); // Aspetta un po' di più per non sovraccaricare

    // Programma aggiornamenti periodici della cache Vavoo (ogni 12 ore)
    const VAVOO_UPDATE_INTERVAL = 12 * 60 * 60 * 1000; // 12 ore in millisecondi
    setInterval(() => {
        console.log(`🔄 Aggiornamento periodico cache Vavoo avviato...`);
        updateVavooCache().then(success => {
            if (success) {
                console.log(`✅ Cache Vavoo aggiornata periodicamente con successo`);
            } else {
                console.log(`⚠️ Aggiornamento periodico cache Vavoo fallito`);
            }
        }).catch(error => {
            console.error(`❌ Errore durante l'aggiornamento periodico cache Vavoo:`, error);
        });
    }, VAVOO_UPDATE_INTERVAL);

    // Programma aggiornamenti periodici della cache TVTap (ogni 12 ore, offset di 1 ora)
    const TVTAP_UPDATE_INTERVAL = 12 * 60 * 60 * 1000; // 12 ore in millisecondi
    setInterval(() => {
        console.log(`🔄 Aggiornamento periodico cache TVTap avviato...`);
        updateTVTapCache().then(success => {
            if (success) {
                console.log(`✅ Cache TVTap aggiornata periodicamente con successo`);
            } else {
                console.log(`⚠️ Aggiornamento periodico cache TVTap fallito`);
            }
        }).catch(error => {
            console.error(`❌ Errore durante l'aggiornamento periodico cache TVTap all'avvio:`, error);
        });
    }, TVTAP_UPDATE_INTERVAL);

    // Inizializza EPG Manager
    if (epgConfig.enabled) {
        epgManager = new EPGManager(epgConfig);
        console.log(`📺 EPG Manager inizializzato con URL: ${epgConfig.epgUrl}`);

        // Avvia aggiornamento EPG in background senza bloccare l'avvio
        setTimeout(() => {
            if (epgManager) {
                epgManager.updateEPG().then(success => {
                    if (success) {
                        console.log(`✅ EPG aggiornato con successo in background`);
                    } else {
                        console.log(`⚠️ Aggiornamento EPG fallito in background, verrà ritentato al prossimo utilizzo`);
                    }
                }).catch(error => {
                    console.error(`❌ Errore durante l'aggiornamento EPG in background:`, error);
                });
            }
        }, 1000);

        // Programma aggiornamenti periodici dell'EPG (ogni 6 ore)
        setInterval(() => {
            if (epgManager) {
                console.log(`🔄 Aggiornamento EPG periodico avviato...`);
                epgManager.updateEPG().then(success => {
                    if (success) {
                        console.log(`✅ EPG aggiornato periodicamente con successo`);
                    } else {
                        console.log(`⚠️ Aggiornamento EPG periodico fallito`);
                    }
                }).catch(error => {
                    console.error(`❌ Errore durante l'aggiornamento EPG periodico:`, error);
                });
            }
        }, epgConfig.updateInterval);
    }
} catch (error) {
    console.error('❌ Errore nel caricamento dei file di configurazione TV:', error);
}


// Funzione per determinare le categorie di un canale
function getChannelCategories(ch: any): string[] {
    const cats = new Set<string>();
    if (ch.category) cats.add(ch.category.toLowerCase().trim());
    if (ch.categories && Array.isArray(ch.categories)) {
        ch.categories.forEach((c: any) => cats.add(String(c).toLowerCase().trim()));
    }
    if (ch.genres && Array.isArray(ch.genres)) {
        ch.genres.forEach((g: any) => cats.add(String(g).toLowerCase().trim()));
    }
    // Deep mapping for common slugs
    const mapping: Record<string, string> = {
        'rai': 'rai', 'mediaset': 'mediaset', 'sky': 'sky', 'kids': 'kids', 'news': 'news', 'sport': 'sport', 'movies': 'movies'
    };
    Array.from(cats).forEach(cat => { if (mapping[cat]) cats.add(mapping[cat]); });
    return Array.from(cats).filter(Boolean);
}

function decodeStaticUrl(url: string | null | undefined): string {
    if (!url) return '';
    let decoded = url;
    if (url.startsWith('base64:')) {
        try { decoded = Buffer.from(url.substring(7), 'base64').toString('utf8'); } catch { }
    }
    return decoded;
}

/**
 * Risolve URL dinamici che richiedono interazione con P🐽G o VAVOO.
 */
async function resolveDynamicEventUrl(url: string, title: string, mfpUrl: string, mfpPsw: string): Promise<{ url: string; title: string }> {
    if (!url) return { url: '', title };

    // Resolve clean Vavoo if needed
    if (url.includes('vavoo.to')) {
        try {
            const reqObj: any = (global as any).lastExpressRequest;
            const clientIp = await getClientIpFromReq(reqObj);
            const clean = await resolveVavooCleanUrl(url, clientIp);
            if (clean && clean.url) {
                const urlWithHeaders = clean.url + '#headers#' + Buffer.from(JSON.stringify(clean.headers)).toString('base64');
                return { url: urlWithHeaders, title };
            }
        } catch (e) {
            debugLog('[DynamicStreams] Vavoo resolution failed:', (e as any)?.message || e);
        }
    }

    // Fallback: use MediaFlow Proxy if credentials present and url isn't already a full URL or is a relative/partial stream
    if (mfpUrl && mfpPsw && (url.includes('.m3u8') || url.includes('.ts'))) {
        const wrapped = `${mfpUrl.replace(/\/$/, '')}/proxy/hls/manifest.m3u8?api_password=${encodeURIComponent(mfpPsw)}&d=${encodeURIComponent(url)}`;
        return { url: wrapped, title };
    }

    return { url, title };
}

// Funzione per assicurarsi che le directory di cache esistano
function ensureCacheDirectories(): void {
    const dirs = [
        path.join(__dirname, '../cache'),
        path.join(__dirname, '../config')
    ];
    for (const d of dirs) {
        if (!fs.existsSync(d)) {
            try { fs.mkdirSync(d, { recursive: true }); } catch { }
        }
    }
}

function normalizeProxyUrl(url: string): string {
    return url.endsWith('/') ? url.slice(0, -1) : url;
}

// Funzione per creare il builder con configurazione dinamica
function createBuilder(initialConfig: AddonConfig = {}) {
    const manifest = loadCustomConfig();
    // Applica un filtro leggero al manifest per nascondere il catalogo TV quando disabilitato
    const effectiveManifest: Manifest = (() => {
        try {
            if (initialConfig && (initialConfig as any).disableLiveTv) {
                const filtered = { ...manifest } as Manifest;
                const cats = Array.isArray(filtered.catalogs) ? filtered.catalogs.slice() : [];
                filtered.catalogs = cats.filter((c: any) => !(c && (c as any).id === 'streamvix_tv'));
                return filtered;
            }
        } catch { }
        return manifest;
    })();

    if (initialConfig.mediaFlowProxyUrl || initialConfig.enableMpd || initialConfig.tmdbApiKey) {
        effectiveManifest.name; // no-op to avoid unused warning pattern
    }

    const builder = new addonBuilder(effectiveManifest);


    // === TV CATALOG HANDLER ONLY ===
    builder.defineCatalogHandler(async ({ type, id, extra }: { type: string; id: string; extra?: any }) => {
        if (type === "tv") {
            try {
                // Simple runtime toggle: hide TV when disabled
                try {
                    const cfg = { ...configCache } as AddonConfig;
                    if (cfg.disableLiveTv) {
                        console.log('📴 TV catalog disabled by config.disableLiveTv');
                        return { metas: [], cacheMaxAge: 0 };
                    }
                } catch { }

                try {
                    const lastReq0: any = (global as any).lastExpressRequest;
                    console.log('📥 Catalog TV request:', {
                        id,
                        extra,
                        path: lastReq0?.path,
                        url: lastReq0?.url
                    });
                } catch { }
                // === Catalogo TV: modalità NO CACHE per test (di default attiva) ===
                const disableCatalogCache = (() => {
                    try {
                        const v = (process?.env?.NO_TV_CATALOG_CACHE ?? '1').toString().toLowerCase();
                        return v === '1' || v === 'true' || v === 'yes' || v === 'on';
                    } catch { return true; }
                })();

                if (disableCatalogCache) {
                    try {
                        // Ricarica sempre dal JSON dinamico e rifai il merge ad ogni richiesta
                        await loadDynamicChannels(true);
                        tvChannels = await mergeDynamic([...staticBaseChannels]);
                        debugLog(`⚡ Catalog rebuilt (NO_CACHE) count=${tvChannels.length}`);
                    } catch (e) {
                        console.error('❌ Merge dynamic channels failed (NO_CACHE):', e);
                    }
                } else {
                    // Fallback: usa cache leggera in memoria
                    const staticSig = staticBaseChannels.length;
                    const cacheKey = `${staticSig}`;
                    const g: any = global as any;
                    if (!g.__tvCatalogCache) g.__tvCatalogCache = { key: '', channels: [], timestamp: 0 };
                    const cacheAge = Date.now() - (g.__tvCatalogCache.timestamp || 0);
                    if (g.__tvCatalogCache.key !== cacheKey || cacheAge > 60000) {
                        try {
                            await loadDynamicChannels(false);
                            tvChannels = await mergeDynamic([...staticBaseChannels]);
                            g.__tvCatalogCache = { key: cacheKey, channels: tvChannels, timestamp: Date.now() };
                            debugLog(`⚡ Catalog rebuild (cache miss or old) newKey=${cacheKey} count=${tvChannels.length}`);
                        } catch (e) {
                            console.error('❌ Merge dynamic channels failed:', e);
                        }
                    } else {
                        tvChannels = g.__tvCatalogCache.channels;
                        debugLog(`⚡ Catalog served from cache key=${cacheKey} count=${tvChannels.length}`);
                    }
                }
                let filteredChannels = tvChannels;
                let requestedSlug: string | null = null;
                let isPlaceholder = false;

                // === SEARCH HANDLER ===
                if (extra && typeof extra.search === 'string' && extra.search.trim().length > 0) {
                    const rawQ = extra.search.trim();
                    const tokens = rawQ.toLowerCase().split(/\s+/).filter(Boolean);
                    console.log(`🔎 Search (OR+fuzzy) query tokens:`, tokens);
                    const seen = new Set<string>();

                    const simpleLevenshtein = (a: string, b: string): number => {
                        if (a === b) return 0;
                        const al = a.length, bl = b.length;
                        if (Math.abs(al - bl) > 1) return 99; // prune (we only care distance 0/1)
                        const dp: number[] = Array(bl + 1).fill(0);
                        for (let j = 0; j <= bl; j++) dp[j] = j;
                        for (let i = 1; i <= al; i++) {
                            let prev = dp[0];
                            dp[0] = i;
                            for (let j = 1; j <= bl; j++) {
                                const tmp = dp[j];
                                if (a[i - 1] === b[j - 1]) dp[j] = prev; else dp[j] = Math.min(prev + 1, dp[j] + 1, dp[j - 1] + 1);
                                prev = tmp;
                            }
                        }
                        return dp[bl];
                    };

                    const tokenMatches = (token: string, hay: string, words: string[]): boolean => {
                        if (!token) return false;
                        if (hay.includes(token)) return true; // substring
                        // prefix match on any word
                        if (words.some(w => w.startsWith(token))) return true;
                        // fuzzy distance 1 on words (only if token length > 3 to avoid noise)
                        if (token.length > 3) {
                            for (const w of words) {
                                if (Math.abs(w.length - token.length) > 1) continue;
                                if (simpleLevenshtein(token, w) <= 1) return true;
                            }
                        }
                        return false;
                    };

                    filteredChannels = tvChannels.filter((c: any) => {
                        const categories = getChannelCategories(c); // include category slugs
                        const categoryStr = categories.join(' ');
                        const hayRaw = `${c.name || ''} ${(c.description || '')} ${categoryStr}`.toLowerCase();
                        const words = hayRaw.split(/[^a-z0-9]+/).filter(Boolean);
                        const ok = tokens.some((t: string) => tokenMatches(t, hayRaw, words)); // OR logic
                        if (ok) {
                            if (seen.has(c.id)) return false;
                            seen.add(c.id);
                            return true;
                        }
                        return false;
                    }).slice(0, 200);
                    console.log(`🔎 Search results (OR+fuzzy): ${filteredChannels.length}`);
                } else {
                    // === GENRE FILTERING (robusto) ===
                    let genreInput: string | undefined;
                    // extra come stringa: "genre=coppe&x=y"
                    if (typeof extra === 'string') {
                        const parts = extra.split('&');
                        for (const p of parts) {
                            const [k, v] = p.split('=');
                            if (k === 'genre' && v) genreInput = decodeURIComponent(v);
                        }
                    }
                    // extra oggetto
                    if (!genreInput && extra && typeof extra === 'object' && extra.genre) genreInput = String(extra.genre);
                    // fallback ultima richiesta express
                    const lastReq: any = (global as any).lastExpressRequest;
                    if (!genreInput && lastReq?.query) {
                        if (typeof lastReq.query.genre === 'string') genreInput = lastReq.query.genre;
                        else if (typeof lastReq.query.extra === 'string') {
                            const m = lastReq.query.extra.match(/genre=([^&]+)/i); if (m) genreInput = decodeURIComponent(m[1]);
                        } else if (lastReq.query.extra && typeof lastReq.query.extra === 'object' && lastReq.query.extra.genre) {
                            genreInput = String(lastReq.query.extra.genre);
                        }
                    }
                    // Fallback: prova ad estrarre genre anche dal path/URL se non presente
                    if (!genreInput) {
                        try {
                            const lastReq2: any = (global as any).lastExpressRequest;
                            const fromUrl = (lastReq2?.url || '') as string;
                            const fromPath = (lastReq2?.path || '') as string;
                            let extracted: string | undefined;
                            // 1) Query string
                            const qMatch = fromUrl.match(/genre=([^&]+)/i);
                            if (qMatch) extracted = decodeURIComponent(qMatch[1]);
                            // 2) Extra nel path: /catalog/tv/tv-channels/genre=Coppe.json oppure .../genre=Coppe&...
                            if (!extracted) {
                                const pMatch = fromPath.match(/\/catalog\/[^/]+\/[^/]+\/([^?]+)\.json/i);
                                if (pMatch && pMatch[1]) {
                                    const extraSeg = decodeURIComponent(pMatch[1]);
                                    const g2 = extraSeg.match(/(?:^|&)genre=([^&]+)/i);
                                    if (g2) extracted = g2[1];
                                    else if (extraSeg.startsWith('genre=')) extracted = extraSeg.split('=')[1];
                                    else if (extraSeg && !extraSeg.includes('=')) extracted = extraSeg; // support /.../Coppe.json
                                }
                            }
                            if (extracted) {
                                genreInput = extracted;
                                console.log(`🔎 Fallback genre extracted from URL/path: '${genreInput}'`);
                            }
                        } catch { }
                    }

                    if (genreInput) {
                        // Normalizza spazi invisibili e accenti
                        genreInput = genreInput.replace(/[\u00A0\u200B\u200C\u200D\uFEFF]/g, ' ').replace(/\s+/g, ' ').trim();
                        const norm = genreInput.trim().toLowerCase()
                            .replace(/[àáâãä]/g, 'a').replace(/[èéêë]/g, 'e')
                            .replace(/[ìíîï]/g, 'i').replace(/[òóôõö]/g, 'o')
                            .replace(/[ùúûü]/g, 'u');
                        const genreMap: { [key: string]: string } = {
                            'rai': 'rai', 'mediaset': 'mediaset', 'sky': 'sky', 'bambini': 'kids', 'news': 'news', 'sport': 'sport', 'cinema': 'movies', 'generali': 'general', 'documentari': 'documentari', 'discovery': 'discovery', 'pluto': 'pluto', 'serie a': 'seriea', 'serie b': 'serieb', 'serie c': 'seriec', 'coppe': 'coppe', 'soccer': 'soccer', 'tennis': 'tennis', 'f1': 'f1', 'motogp': 'motogp', 'basket': 'basket', 'volleyball': 'volleyball', 'ice hockey': 'icehockey', 'wrestling': 'wrestling', 'boxing': 'boxing', 'darts': 'darts', 'baseball': 'baseball', 'nfl': 'nfl'
                        };
                        // Aggiungi mapping per nuove leghe
                        genreMap['premier league'] = 'premierleague';
                        genreMap['liga'] = 'liga';
                        genreMap['bundesliga'] = 'bundesliga';
                        genreMap['ligue 1'] = 'ligue1';
                        const target = genreMap[norm] || norm;
                        requestedSlug = target;
                        filteredChannels = tvChannels.filter(ch => getChannelCategories(ch).includes(target));
                        console.log(`🔍 Genre='${norm}' -> slug='${target}' results=${filteredChannels.length}`);
                    } else {
                        console.log(`📺 No genre filter, showing all ${tvChannels.length} channels`);
                    }
                }

                // Se filtro richiesto e nessun canale trovato -> aggiungi placeholder
                if (requestedSlug && filteredChannels.length === 0) {
                    const PLACEHOLDER_ID = `placeholder-${requestedSlug}`;
                    const PLACEHOLDER_LOGO_BASE = 'https://raw.githubusercontent.com/qwertyuiop8899/logo/main';
                    const placeholderLogo = `${PLACEHOLDER_LOGO_BASE}/nostream.png`;
                    filteredChannels = [{
                        id: PLACEHOLDER_ID,
                        name: 'Nessuno Stream disponibile oggi',
                        logo: placeholderLogo,
                        poster: placeholderLogo,
                        type: 'tv',
                        category: [requestedSlug],
                        genres: [requestedSlug],
                        description: 'Nessuno Stream disponibile oggi. Live 🔴',
                        _placeholder: true,
                        placeholderVideo: `${PLACEHOLDER_LOGO_BASE}/nostream.mp4`
                    }];
                    isPlaceholder = true;
                }

                // Ordina SOLO gli eventi dinamici per eventStart (asc) quando è presente un filtro di categoria
                try {
                    if (requestedSlug && filteredChannels.length) {
                        const dynWithIndex = filteredChannels
                            .map((ch: any, idx: number) => ({ ch, idx }))
                            .filter(x => !!x.ch && (x.ch as any)._dynamic);
                        const compare = (a: any, b: any) => {
                            const aS = a?.eventStart || a?.eventstart;
                            const bS = b?.eventStart || b?.eventstart;
                            const ap = aS ? Date.parse(aS) : NaN;
                            const bp = bS ? Date.parse(bS) : NaN;
                            const aHas = !isNaN(ap);
                            const bHas = !isNaN(bp);
                            if (aHas && bHas) return ap - bp;
                            if (aHas && !bHas) return -1;
                            if (!aHas && bHas) return 1;
                            return (a?.name || '').localeCompare(b?.name || '');
                        };
                        dynWithIndex.sort((A, B) => compare(A.ch, B.ch));
                        const sortedDyn = dynWithIndex.map(x => x.ch);
                        let di = 0;
                        filteredChannels = filteredChannels.map((ch: any) => ch && (ch as any)._dynamic ? sortedDyn[di++] : ch);
                        console.log(`⏱️ Sorted only dynamic events within category '${requestedSlug}' (asc)`);
                    }
                } catch { }

                // Aggiungi prefisso tv: agli ID, posterShape landscape e EPG
                const tvChannelsWithPrefix = await Promise.all(filteredChannels.map(async (channel: any) => {
                    const channelWithPrefix = {
                        ...channel,
                        id: `tv:${channel.id}`,
                        posterShape: "landscape",
                        poster: (channel as any).poster || (channel as any).logo || '',
                        logo: (channel as any).logo || (channel as any).poster || '',
                        background: (channel as any).background || (channel as any).poster || ''
                    };

                    // Per canali dinamici: niente EPG, mostra solo ora inizio evento
                    if ((channel as any)._dynamic) {
                        const eventStart = (channel as any).eventStart || (channel as any).eventstart; // fallback
                        const stripTimePrefix = (t: string): string => t.replace(/^\s*([⏰🕒]?\s*)?\d{1,2}[\.:]\d{2}\s*[:\-]\s*/i, '').trim();
                        if (eventStart) {
                            try {
                                const hhmm = epgManager ? epgManager.formatDynamicHHMM(eventStart) : new Date(eventStart).toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', hour12: false }).replace(/\./g, ':');
                                const ddmm = epgManager ? epgManager.formatDynamicDDMM(eventStart) : '';
                                const rawTitle = stripTimePrefix(channel.name || '');
                                const parts = rawTitle.split(' - ').map(s => s.trim()).filter(Boolean);
                                const eventTitle = parts[0] || rawTitle;
                                // Deriva league + date + country dal resto
                                let tail = parts.slice(1).join(' - ');
                                const dateMatch = rawTitle.match(/\b(\d{1,2}\/\d{1,2})\b/);
                                const dateStr = dateMatch?.[1] || ddmm;
                                const hasItaly = /\bitaly\b/i.test(rawTitle);
                                // Rimuovi date/country dal tail per ottenere la lega pulita
                                let league = tail
                                    .replace(/\b(\d{1,2}\/\d{1,2})\b/gi, '')
                                    .replace(/\bitaly\b/gi, '')
                                    .replace(/\s{2,}/g, ' ')
                                    .replace(/^[-–—\s]+|[-–—\s]+$/g, '')
                                    .trim();
                                // Titolo canale: Evento ⏰ HH:MM - DD/MM (senza Italy, senza lega)
                                (channelWithPrefix as any).name = `${eventTitle} ⏰ ${hhmm}${dateStr ? ` - ${dateStr}` : ''}`;
                                // Summary: 🔴 Inizio: HH:MM - Evento - Lega - DD/MM Italy
                                channelWithPrefix.description = `🔴 Inizio: ${hhmm} - ${eventTitle}${league ? ` - ${league}` : ''}${dateStr ? ` - ${dateStr}` : ''}${hasItaly ? ' Italy' : ''}`.trim();
                            } catch {
                                channelWithPrefix.description = channel.name || '';
                            }
                        } else {
                            // Se manca l'orario, mantieni nome e descrizione originali
                            channelWithPrefix.description = channel.name || '';
                        }
                    } else if (epgManager) {
                        // Canali tradizionali: EPG
                        try {
                            const epgChannelIds = (channel as any).epgChannelIds;
                            const epgChannelId = epgManager.findEPGChannelId(channel.name, epgChannelIds);
                            if (epgChannelId) {
                                const currentProgram = await epgManager.getCurrentProgram(epgChannelId);
                                if (currentProgram) {
                                    const startTime = epgManager.formatTime(currentProgram.start, 'live');
                                    const endTime = currentProgram.stop ? epgManager.formatTime(currentProgram.stop, 'live') : '';
                                    const epgInfo = `🔴 ORA: ${currentProgram.title} (${startTime}${endTime ? `-${endTime}` : ''})`;
                                    channelWithPrefix.description = `${channel.description || ''}\n\n${epgInfo}`;
                                }
                            }
                        } catch (epgError) {
                            console.error(`❌ Catalog: EPG error for ${channel.name}:`, epgError);
                        }
                    }

                    return channelWithPrefix;
                }));

                console.log(`✅ Returning ${tvChannelsWithPrefix.length} TV channels for catalog ${id}${isPlaceholder ? ' (placeholder, cacheMaxAge=0)' : ''}`);
                return isPlaceholder
                    ? { metas: tvChannelsWithPrefix, cacheMaxAge: 0 }
                    : { metas: tvChannelsWithPrefix };
            } catch (err) {
                console.error(`❌ Catalog TV error (trap):`, err);
                return { metas: [], cacheMaxAge: 0 };
            }
        }
        console.log(`❌ No catalog found for type=${type}, id=${id}`);
        return { metas: [] };
    });

    // === HANDLER META ===
    builder.defineMetaHandler(async ({ type, id }: { type: string; id: string }) => {
        console.log(`📺 META REQUEST: type=${type}, id=${id}`);
        if (type === "tv") {
            try {
                const cfg2 = { ...configCache } as AddonConfig;
                if (cfg2.disableLiveTv) {
                    console.log('📴 TV meta disabled by config.disableLiveTv');
                    return { meta: null };
                }
            } catch { }
            // Gestisci tutti i possibili formati di ID che Stremio può inviare
            let cleanId = id;
            if (id.startsWith('tv:')) {
                cleanId = id.replace('tv:', '');
            } else if (id.startsWith('tv%3A')) {
                cleanId = id.replace('tv%3A', '');
            } else if (id.includes('%3A')) {
                // Decodifica URL-encoded (:)
                cleanId = decodeURIComponent(id);
                if (cleanId.startsWith('tv:')) {
                    cleanId = cleanId.replace('tv:', '');
                }
            }

            const channel = tvChannels.find((c: any) => c.id === cleanId);
            if (channel) {
                console.log(`✅ Found channel for meta: ${channel.name}`);

                const metaWithPrefix = {
                    ...channel,
                    id: `tv:${channel.id}`,
                    posterShape: "landscape",
                    poster: (channel as any).poster || (channel as any).logo || '',
                    logo: (channel as any).logo || (channel as any).poster || '',
                    background: (channel as any).background || (channel as any).poster || '',
                    genre: Array.isArray((channel as any).category) ? (channel as any).category : [(channel as any).category || 'general'],
                    genres: Array.isArray((channel as any).category) ? (channel as any).category : [(channel as any).category || 'general'],
                    year: new Date().getFullYear().toString(),
                    imdbRating: null,
                    releaseInfo: "Live TV",
                    country: "IT",
                    language: "it"
                };

                // Meta: canali dinamici senza EPG con ora inizio
                if ((channel as any)._dynamic) {
                    const eventStart = (channel as any).eventStart || (channel as any).eventstart;
                    let finalDesc = channel.name || '';
                    const stripTimePrefix = (t: string): string => t.replace(/^\s*([⏰🕒]?\s*)?\d{1,2}[\.:]\d{2}\s*[:\-]\s*/i, '').trim();
                    if (eventStart) {
                        try {
                            const hhmm = epgManager ? epgManager.formatDynamicHHMM(eventStart) : new Date(eventStart).toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', hour12: false }).replace(/\./g, ':');
                            const ddmm = epgManager ? epgManager.formatDynamicDDMM(eventStart) : '';
                            const rawTitle = stripTimePrefix(channel.name || '');
                            const parts = rawTitle.split(' - ').map(s => s.trim()).filter(Boolean);
                            const eventTitle = parts[0] || rawTitle;
                            let tail = parts.slice(1).join(' - ');
                            const dateMatch = rawTitle.match(/\b(\d{1,2}\/\d{1,2})\b/);
                            const dateStr = dateMatch?.[1] || ddmm;
                            const hasItaly = /\bitaly\b/i.test(rawTitle);
                            let league = tail
                                .replace(/\b(\d{1,2}\/\d{1,2})\b/gi, '')
                                .replace(/\bitaly\b/gi, '')
                                .replace(/\s{2,}/g, ' ')
                                .replace(/^[-–—\s]+|[-–—\s]+$/g, '')
                                .trim();
                            // Nome coerente anche nel meta: Evento ⏰ HH:MM - DD/MM
                            (metaWithPrefix as any).name = `${eventTitle} ⏰ ${hhmm}${dateStr ? ` - ${dateStr}` : ''}`;
                            finalDesc = `🔴 Inizio: ${hhmm} - ${eventTitle}${league ? ` - ${league}` : ''}${dateStr ? ` - ${dateStr}` : ''}${hasItaly ? ' Italy' : ''}`.trim();
                        } catch {/* ignore */ }
                    }
                    (metaWithPrefix as any).description = finalDesc;
                } else if (epgManager) {
                    // Meta: canali tradizionali con EPG
                    try {
                        const epgChannelIds = (channel as any).epgChannelIds;
                        const epgChannelId = epgManager.findEPGChannelId(channel.name, epgChannelIds);
                        if (epgChannelId) {
                            const currentProgram = await epgManager.getCurrentProgram(epgChannelId);
                            const nextProgram = await epgManager.getNextProgram(epgChannelId);
                            let epgDescription = channel.description || '';
                            if (currentProgram) {
                                const startTime = epgManager.formatTime(currentProgram.start, 'live');
                                const endTime = currentProgram.stop ? epgManager.formatTime(currentProgram.stop, 'live') : '';
                                epgDescription += `\n\n🔴 IN ONDA ORA (${startTime}${endTime ? `-${endTime}` : ''}): ${currentProgram.title}`;
                                if (currentProgram.description) epgDescription += `\n${currentProgram.description}`;
                            }
                            if (nextProgram) {
                                const nextStartTime = epgManager.formatTime(nextProgram.start, 'live');
                                const nextEndTime = nextProgram.stop ? epgManager.formatTime(nextProgram.stop, 'live') : '';
                                epgDescription += `\n\n⏭️ A SEGUIRE (${nextStartTime}${nextEndTime ? `-${nextEndTime}` : ''}): ${nextProgram.title}`;
                                if (nextProgram.description) epgDescription += `\n${nextProgram.description}`;
                            }
                            metaWithPrefix.description = epgDescription;
                        }
                    } catch (epgError) {
                        console.error(`❌ Meta: EPG error for ${channel.name}:`, epgError);
                    }
                }

                return { meta: metaWithPrefix };
            } else {
                // Fallback per placeholder non persistiti in tvChannels
                if (cleanId.startsWith('placeholder-')) {
                    const slug = cleanId.replace('placeholder-', '') || 'general';
                    const PLACEHOLDER_LOGO_BASE = 'https://raw.githubusercontent.com/qwertyuiop8899/logo/main';
                    const placeholderLogo = `${PLACEHOLDER_LOGO_BASE}/nostream.png`;
                    const placeholderVideo = `${PLACEHOLDER_LOGO_BASE}/nostream.mp4`;
                    const name = 'Nessuno Stream disponibile oggi';
                    const meta = {
                        id: `tv:${cleanId}`,
                        type: 'tv',
                        name,
                        posterShape: 'landscape',
                        poster: placeholderLogo,
                        logo: placeholderLogo,
                        background: placeholderLogo,
                        description: 'Nessuno Stream disponibile oggi. Live 🔴',
                        genre: [slug],
                        genres: [slug],
                        year: new Date().getFullYear().toString(),
                        imdbRating: null,
                        releaseInfo: 'Live TV',
                        country: 'IT',
                        language: 'it',
                        _placeholder: true,
                        placeholderVideo
                    } as any;
                    console.log(`🧩 Generated dynamic placeholder meta for missing channel ${cleanId}`);
                    return { meta };
                }
                console.log(`❌ No meta found for channel ID: ${id}`);
                return { meta: null };
            }
        }

        // Meta handler per film/serie (logica originale)
        return { meta: null };
    });


    // === HANDLER STREAM ===
    builder.defineStreamHandler(
        async ({
            id,
            type,
        }: {
            id: string;
            type: string;
        }): Promise<{
            streams: Stream[];
        }> => {
            try {
                console.log(`ðŸ” Stream request: ${type}/${id}`);

                // âœ… USA SEMPRE la configurazione dalla cache globale piÃ¹ aggiornata
                const config = { ...configCache };
                console.log(`ðŸ”§ Using global config cache for stream:`, config);

                const allStreams: Stream[] = [];

                // Prima della logica degli stream TV, aggiungi:
                // Usa sempre lo stesso proxy per tutto
                // MediaFlow config: allow fallback to environment variables if not provided via addon config
                let mfpUrlRaw = '';
                let mfpPswRaw = '';
                try {
                    mfpUrlRaw = (config.mediaFlowProxyUrl || (process && process.env && (process.env.MFP_URL || process.env.MEDIAFLOW_PROXY_URL)) || '').toString().trim();
                    mfpPswRaw = (config.mediaFlowProxyPassword || (process && process.env && (process.env.MFP_PASSWORD || process.env.MEDIAFLOW_PROXY_PASSWORD)) || '').toString().trim();
                } catch { }
                let mfpUrl = mfpUrlRaw ? normalizeProxyUrl(mfpUrlRaw) : '';
                let mfpPsw = mfpPswRaw;
                debugLog(`[MFP] Using url=${mfpUrl ? 'SET' : 'MISSING'} pass=${mfpPsw ? 'SET' : 'MISSING'}`);

                // === LOGICA TV ===

                if (type === "tv") {
                    // Runtime disable live TV
                    try {
                        const cfg2 = { ...configCache } as AddonConfig;
                        if (cfg2.disableLiveTv) {
                            console.log('📴 TV streams disabled by config.disableLiveTv');
                            return { streams: [] };
                        }
                    } catch { }
                    // Assicura che i canali dinamici siano presenti anche se la prima richiesta è uno stream (senza passare dal catalog)
                    try {
                        await loadDynamicChannels(false);
                        tvChannels = await mergeDynamic([...staticBaseChannels]);
                    } catch (e) {
                        console.error('❌ Stream handler: mergeDynamic failed:', e);
                    }
                    // Improved channel ID parsing to handle different formats from Stremio
                    let cleanId = id;

                    // Gestisci tutti i possibili formati di ID che Stremio può inviare
                    // if (id.startsWith('freeshot:')) {
                    //     return await getFreeshotStream(id, config);
                    // }
                    if (id.startsWith('tv:')) {
                        cleanId = id.replace('tv:', '');
                    } else if (id.startsWith('tv%3A')) {
                        cleanId = id.replace('tv%3A', '');
                    } else if (id.includes('%3A')) {
                        // Decodifica URL-encoded (:)
                        cleanId = decodeURIComponent(id);
                        if (cleanId.startsWith('tv:')) {
                            cleanId = cleanId.replace('tv:', '');
                        }
                    }

                    debugLog(`Looking for channel with ID: ${cleanId} (original ID: ${id})`);
                    const channel = tvChannels.find((c: any) => c.id === cleanId);

                    if (!channel) {
                        // Gestione placeholder non presente in tvChannels
                        if (cleanId.startsWith('placeholder-')) {
                            const PLACEHOLDER_LOGO_BASE = 'https://raw.githubusercontent.com/qwertyuiop8899/logo/main';
                            const placeholderVideo = `${PLACEHOLDER_LOGO_BASE}/nostream.mp4`;
                            console.log(`🧩 Placeholder channel requested (ephemeral): ${cleanId}`);
                            return { streams: [{ url: placeholderVideo, title: 'Nessuno Stream' }] };
                        }
                        console.log(`❌ Channel ${id} not found`);
                        debugLog(`❌ Channel not found in the TV channels list. Original ID: ${id}, Clean ID: ${cleanId}`);
                        return { streams: [] };
                    }

                    // Gestione placeholder: ritorna un singolo "stream" fittizio (immagine)
                    if ((channel as any)._placeholder) {
                        const vid = (channel as any).placeholderVideo || (channel as any).logo || (channel as any).poster || '';
                        return {
                            streams: [{
                                url: vid,
                                title: 'Nessuno Stream'
                            }]
                        };
                    }

                    console.log(`✅ Found channel: ${channel.name}`);

                    // Debug della configurazione proxy
                    debugLog(`Config DEBUG - mediaFlowProxyUrl: ${config.mediaFlowProxyUrl}`);
                    debugLog(`Config DEBUG - mediaFlowProxyPassword: ${config.mediaFlowProxyPassword ? '***' : 'NOT SET'}`);

                    let streams: { url: string; title: string }[] = [];
                    const vavooCleanPromises: Promise<void>[] = [];
                    // Collect clean Vavoo results per variant index to prepend in order later
                    const vavooCleanPrepend: Array<{ url: string; title: string } | undefined> = [];
                    // Keep track of found Vavoo variant URLs to allow fallback insertion
                    const vavooFoundUrls: string[] = [];
                    // Stato toggle MPD (solo da config checkbox, niente override da env per evitare comportamento inatteso)
                    const mpdEnabled = !!config.enableMpd;

                    // Dynamic event channels: dynamicDUrls -> usa stessa logica avanzata di staticUrlD per estrarre link finale
                    if ((channel as any)._dynamic) {
                        const dArr = Array.isArray((channel as any).dynamicDUrls) ? (channel as any).dynamicDUrls : [];
                        console.log(`[DynamicStreams] Channel ${channel.id} dynamicDUrls count=${dArr.length}`);
                        if (dArr.length === 0) {
                            console.log(`[DynamicStreams] ⚠️ Nessuno stream dinamico presente nel canale (dynamicDUrls vuoto)`);
                        }
                        // Click-time Vavoo injection: se trovi un canale "con la bandierina" (titolo provider), prova a mappare su Vavoo
                        try {
                            const providerTitles = dArr.map((e: any) => String(e?.title || '')).filter(Boolean);
                            // dai la priorità a titoli che contengono indicatori italiani
                            const itaPrefer = providerTitles.filter((t: string) => /\b(it|ita|italy|italia|italian|italiano|sky|dazn|eurosport|rai|now)\b/i.test(t));
                            const candidateTexts = itaPrefer.length ? itaPrefer : providerTitles;
                            const alias = findBestAliasInTexts(candidateTexts);
                            if (alias) {
                                const vUrl = resolveFirstVavooUrlForAlias(alias);
                                if (vUrl) {
                                    // Only prepend the CLEAN non-MFP link (per-request, with headers)
                                    const reqObj: any = (global as any).lastExpressRequest;
                                    const clientIp = await getClientIpFromReq(reqObj);
                                    let vavooCleanResolved: { url: string; headers: Record<string, string> } | null = null;
                                    try {
                                        const clean = await resolveVavooCleanUrl(vUrl, clientIp);
                                        if (clean && clean.url) {
                                            vavooCleanResolved = clean;
                                            vdbg('Alias clean resolved', { alias, url: clean.url.substring(0, 140) });
                                            const title2 = `🏠 ${alias} (Vavoo🔓) [ITA]`;
                                            // stash headers via behaviorHints when pushing later
                                            streams.unshift({ url: clean.url + `#headers#` + Buffer.from(JSON.stringify(clean.headers)).toString('base64'), title: title2 });
                                        }
                                    } catch (ee) {
                                        const msg = (ee as any)?.message || ee;
                                        vdbg('Alias clean resolve failed', { alias, error: msg });
                                        console.log('[VAVOO] Clean resolve skipped/failed:', msg);
                                    }
                                    // Iniezione Vavoo/MFP: incapsula SEMPRE l'URL vavoo.to originale (come in Live TV), senza extractor
                                    try {
                                        if (mfpUrl && mfpPsw) {
                                            const finalUrl2 = `${mfpUrl}/proxy/hls/manifest.m3u8?d=${encodeURIComponent(vUrl)}&api_password=${encodeURIComponent(mfpPsw)}`;
                                            const title3 = `🌐 ${alias} (Vavoo/MFP) [ITA]`;
                                            let insertAt = 0;
                                            try { if (streams.length && /(\(Vavoo\))/i.test(streams[0].title)) insertAt = 1; } catch { }
                                            try { streams.splice(insertAt, 0, { url: finalUrl2, title: title3 }); } catch { streams.push({ url: finalUrl2, title: title3 }); }
                                            vdbg('Alias Vavoo/MFP injected (direct proxy/hls on vUrl)', { alias, url: finalUrl2.substring(0, 140) });
                                        } else {
                                            vdbg('Skip Vavoo/MFP injection: MFP config missing');
                                        }
                                    } catch (e2) {
                                        vdbg('Vavoo/MFP injection error', String((e2 as any)?.message || e2));
                                    }
                                    // Iniezioni extra: DAZN ZONA IT -> usa staticUrlMpd di 'dazn1'; EUROSPORT 1/2 IT -> usa staticUrlMpd di 'eurosport1'/'eurosport2'
                                    try {
                                        const textsScan: string[] = [channel?.name || '', ...candidateTexts].map(t => (t || '').toLowerCase());
                                        const hasDaznZonaIt = textsScan.some(t => /dazn\s*zona\s*it/.test(t));
                                        const hasEu1It = textsScan.some(t => /eurosport\s*1/.test(t) && /\bit\b/.test(t));
                                        const hasEu2It = textsScan.some(t => /eurosport\s*2/.test(t) && /\bit\b/.test(t));
                                        const injectFromStaticMpd = async (staticId: string) => {
                                            try {
                                                const base = (staticBaseChannels || []).find((c: any) => c && c.id === staticId);
                                                if (!base || !base.staticUrlMpd) return;
                                                const decodedUrl = decodeStaticUrl(base.staticUrlMpd);
                                                let finalUrl = decodedUrl;
                                                let proxyUsed = false;
                                                if (mfpUrl && mfpPsw) {
                                                    const urlParts = decodedUrl.split('&');
                                                    const baseUrl = urlParts[0];
                                                    const additionalParams = urlParts.slice(1);
                                                    finalUrl = `${mfpUrl}/proxy/mpd/manifest.m3u8?api_password=${encodeURIComponent(mfpPsw)}&d=${encodeURIComponent(baseUrl)}`;
                                                    for (const param of additionalParams) if (param) finalUrl += `&${param}`;
                                                    proxyUsed = true;
                                                }
                                                const title = `${proxyUsed ? '' : '[❌Proxy]'}[🎬MPD] ${base.name} [ITA]`;
                                                let insertAt = 0;
                                                try { while (insertAt < streams.length && /(\(Vavoo🔓\))/i.test(streams[insertAt].title)) insertAt++; } catch { }
                                                try { streams.splice(insertAt, 0, { url: finalUrl, title }); } catch { streams.push({ url: finalUrl, title }); }
                                                vdbg('Injected staticUrlMpd from static channel', { id: staticId, url: finalUrl.substring(0, 140) });
                                            } catch { }
                                        };
                                        if (hasDaznZonaIt) await injectFromStaticMpd('dazn1');
                                        if (hasEu1It) await injectFromStaticMpd('eurosport1');
                                        if (hasEu2It) await injectFromStaticMpd('eurosport2');
                                    } catch { }
                                    console.log(`✅ [VAVOO] Injected first stream from alias='${alias}' -> ${vUrl.substring(0, 60)}...`);
                                } else {
                                    console.log(`⚠️ [VAVOO] Alias trovato ma nessun URL in cache: '${alias}'`);
                                }
                            } else {
                                console.log('[VAVOO] Nessun alias broadcaster riconosciuto nei titoli provider');
                            }
                        } catch (e) {
                            console.error('❌ [VAVOO] Errore injection dinamico:', (e as any)?.message || e);
                        }
                    }
                    let dynamicHandled = false;
                    // FAST DIRECT MODE opzionale (solo se esplicitamente richiesto via env FAST_DYNAMIC=1)
                    // FAST_DYNAMIC: se impostato a 1/true salta extractor e usa URL dirette dal JSON
                    const fastDynamic = (process.env.FAST_DYNAMIC === '1' || process.env.FAST_DYNAMIC === 'true');
                    if ((channel as any)._dynamic && Array.isArray((channel as any).dynamicDUrls) && (channel as any).dynamicDUrls.length && fastDynamic) {
                        debugLog(`[DynamicStreams] FAST branch attiva (FAST_DYNAMIC=1) canale=${channel.id}`);
                        let entries: { url: string; title?: string }[] = (channel as any).dynamicDUrls.map((e: any) => ({
                            url: e.url,
                            title: (e.title || 'Stream').replace(/^\s*\[(FAST|Player Esterno)\]\s*/i, '').trim()
                        }));
                        const capRaw = parseInt(process.env.DYNAMIC_EXTRACTOR_CONC || '10', 10);
                        const CAP = Math.min(Math.max(1, isNaN(capRaw) ? 10 : capRaw), 50);
                        if (entries.length > CAP) {
                            const tier1Regex = /\b(it|ita|italy|italia)\b/i;
                            // Aggiunto vavoo e p🐽d per mantenerli nel taglio CAP (richiesta visibilità)
                            const tier2Regex = /\b(italian|italiano|sky|tnt|amazon|dazn|eurosport|prime|bein|canal|sportitalia|now|rai|vavoo|strd|rbtv|rb77|spso|pd)\b|p🐽d/i;
                            const tier1: typeof entries = [];
                            const tier2: typeof entries = [];
                            const others: typeof entries = [];
                            for (const e of entries) {
                                const t = (e.title || '').toLowerCase();
                                if (tier1Regex.test(t)) tier1.push(e);
                                else if (tier2Regex.test(t)) tier2.push(e);
                                else others.push(e);
                            }
                            entries = [...tier1, ...tier2, ...others].slice(0, CAP);
                            debugLog(`[DynamicStreams][FAST] limit ${CAP} applied tier1=${tier1.length} tier2=${tier2.length} total=${(channel as any).dynamicDUrls.length}`);
                        }
                        const fastStartIndex = streams.length; // indice da cui iniziano gli stream FAST
                        for (const e of entries) {
                            if (!e || !e.url) continue;
                            let t = (e.title || 'Stream').trim();
                            if (!t) t = 'Stream';
                            t = t.replace(/^\s*\[(FAST|Player Esterno)\]\s*/i, '').trim();
                            // Aggiungi prefisso [Player Esterno] salvo casi speciali (Strd / RB77 / SPSO / PD / dTV)
                            // Include SPSO e consente [Strd] senza spazio successivo
                            if (!/^\[(Strd|RB77|SPSO|P🐽D|🌍dTV)\b/.test(t)) t = `[Player Esterno] ${t}`;
                            streams.push({ url: e.url, title: t });
                        }
                        // Duplicazione CF per canali italiani nel ramo FAST (logica analoga a EXTRACTOR)
                        try {
                            const cfPrefix = 'https://proxy.stremio.dpdns.org/manifest.m3u8?url=';
                            const itaRegex = /\b(it|ita|italy|italia)\b/i;
                            const addedFast = streams.slice(fastStartIndex); // solo quelli appena aggiunti
                            const enrichedFast: { url: string; title: string }[] = [];
                            for (const s of addedFast) {
                                if (!s || !s.url) continue;
                                // Normalizza bandiera se manca ma titolo finisce con IT/ita...
                                if (!s.title.startsWith('🇮🇹')) {
                                    const bare = s.title.replace(/^\[Player Esterno\]\s*/, '').trim();
                                    if (itaRegex.test(bare)) {
                                        s.title = `🇮🇹 ${bare}`; // aggiorna in place
                                    }
                                }
                            }
                            for (const s of addedFast) {
                                enrichedFast.push(s as any);
                                if (!s.title.startsWith('🇮🇹')) continue; // solo italiani
                                if (s.url.startsWith(cfPrefix)) continue; // già proxy
                                if (!/dlhd\.dad\/watch\.php\?id=\d+/i.test(s.url)) continue; // solo link dlhd.dad originali
                                const proxyUrl = cfPrefix + s.url;
                                if (streams.some(x => x.url === proxyUrl)) continue; // evita duplicati globali
                                const dupTitle = s.title.replace(/^🇮🇹\s*/, '🇮🇹🔄 ');
                                enrichedFast.push({ url: proxyUrl, title: dupTitle });
                            }
                            // Sostituisci la sezione FAST con arricchita (mantieni parte precedente invariata)
                            streams.splice(fastStartIndex, addedFast.length, ...enrichedFast);
                        } catch (e) {
                            // silenzia errori duplicazione fast
                        }
                        debugLog(`[DynamicStreams][FAST] restituiti ${streams.length} stream diretti (senza extractor) con etichetta condizionale 'Player Esterno'`);
                        // Filtro minimale senza MFP: rimuovi solo gli URL diretti dlhd.dad (lascia tutto il resto)
                        if (!(mfpUrl && mfpPsw)) {
                            const beforeFast = streams.length;
                            for (let i = streams.length - 1; i >= 0; i--) {
                                if (/^https?:\/\/dlhd\.dad\/watch\.php\?id=\d+/i.test(streams[i].url)) streams.splice(i, 1);
                            }
                            if (beforeFast !== streams.length) debugLog(`[DynamicStreams][FAST][NO_MFP] rimossi ${beforeFast - streams.length} dlhd.dad, rimasti=${streams.length}`);
                        }
                        dynamicHandled = true;
                    } else if ((channel as any)._dynamic && Array.isArray((channel as any).dynamicDUrls) && (channel as any).dynamicDUrls.length) {
                        debugLog(`[DynamicStreams] EXTRACTOR branch attiva (FAST_DYNAMIC disattivato) canale=${channel.id}`);
                        const startDyn = Date.now();
                        let entries: { url: string; title?: string }[] = (channel as any).dynamicDUrls.map((e: any) => ({
                            url: e.url,
                            title: (e.title || 'Stream').replace(/^\s*\[(FAST|Player Esterno)\]\s*/i, '').trim()
                        }));
                        const maxConcRaw = parseInt(process.env.DYNAMIC_EXTRACTOR_CONC || '10', 10);
                        const CAP = Math.min(Math.max(1, isNaN(maxConcRaw) ? 10 : maxConcRaw), 50);
                        let extraFast: { url: string; title?: string }[] = [];
                        if (entries.length > CAP) {
                            // Tiered priority: tier1 strictly (it|ita|italy) first, then tier2 broader providers, then rest
                            const tier1Regex = /\b(it|ita|italy|italia)\b/i;
                            // Aggiunto vavoo e p🐽d per evitare esclusione dal CAP
                            const tier2Regex = /\b(italian|italiano|sky|tnt|amazon|dazn|eurosport|prime|bein|canal|sportitalia|now|rai|vavoo|strd|rbtv|rb77|spso|pd)\b|p🐽d/i;
                            const tier1: typeof entries = [];
                            const tier2: typeof entries = [];
                            const others: typeof entries = [];
                            for (const e of entries) {
                                const t = (e.title || '').toLowerCase();
                                if (tier1Regex.test(t)) tier1.push(e);
                                else if (tier2Regex.test(t)) tier2.push(e);
                                else others.push(e);
                            }
                            const ordered = [...tier1, ...tier2, ...others];
                            entries = ordered.slice(0, CAP);
                            extraFast = ordered.slice(CAP); // fallback direct for remaining
                            debugLog(`[DynamicStreams][EXTRACTOR] cap ${CAP} applied tier1=${tier1.length} tier2=${tier2.length} extraFast=${extraFast.length} total=${(channel as any).dynamicDUrls.length}`);
                        }
                        const resolved: { url: string; title: string }[] = [];
                        const itaRegex = /\b(it|ita|italy|italia|italian|italiano)$/i;
                        const CONCURRENCY = Math.min(entries.length, CAP); // Extract up to CAP in parallel (bounded by entries)
                        let index = 0;
                        const worker = async () => {
                            while (true) {
                                const i = index++;
                                if (i >= entries.length) break;
                                const d = entries[i];
                                if (!d || !d.url) continue;
                                let providerTitle = (d.title || 'Stream').trim().replace(/^\((.*)\)$/, '$1').trim();
                                if (itaRegex.test(providerTitle) && !providerTitle.startsWith('🇮🇹')) providerTitle = `🇮🇹 ${providerTitle}`;
                                try {
                                    const r = await resolveDynamicEventUrl(d.url, providerTitle, mfpUrl, mfpPsw);
                                    // Conserva indice ed originale per fallback duplicazione CF
                                    (resolved as any).push({ ...r, _idx: i, _orig: d.url });
                                } catch (e) {
                                    debugLog('[DynamicStreams] extractor errore singolo stream:', (e as any)?.message || e);
                                }
                            }
                        };
                        await Promise.all(Array(Math.min(CONCURRENCY, entries.length)).fill(0).map(() => worker()));
                        resolved.sort((a, b) => {
                            const itaA = a.title.startsWith('🇮🇹') ? 0 : 1;
                            const itaB = b.title.startsWith('🇮🇹') ? 0 : 1;
                            if (itaA !== itaB) return itaA - itaB;
                            return a.title.localeCompare(b.title);
                        });
                        // (rimosso logging dettagliato RESOLVED per produzione)
                        // Duplica gli stream italiani (non ancora estratti) con variante proxy CF
                        // Regola: solo quelli che iniziano con bandiera italiana e NON già duplicati
                        const cfPrefix = 'https://proxy.stremio.dpdns.org/manifest.m3u8?url=';
                        const enriched: { url: string; title: string }[] = [];
                        for (const rAny of resolved as any[]) {
                            const r = rAny as any;
                            enriched.push(r); // originale estratto (MFP / o direct se fallback)
                            try {
                                // Non duplicare se l'URL è già un proxy CF o se NON è italiano
                                if (!r.title.startsWith('🇮🇹')) continue;
                                if (r.url.startsWith(cfPrefix)) continue;
                                // Heuristic: se l'URL contiene già /proxy/hls/manifest.m3u8 (MFP) allora saltiamo: vogliamo solo duplicare l'ORIGINALE pre-extractor.
                                // Tuttavia qui r.url è già il risultato di resolveDynamicEventUrl (che incapsula MFP). Quindi per rispettare richiesta "prima di mfp"
                                // proviamo a ricostruire la url originale se possibile: se contiene parametro d= decodifichiamo quello.
                                let originalCandidate = r.url;
                                try {
                                    const u = new URL(r.url);
                                    const dParam = u.searchParams.get('d');
                                    if (dParam) originalCandidate = decodeURIComponent(dParam);
                                } catch { }
                                // Fallback: se manca d= usa l'originale salvato (_orig)
                                if (!/dlhd\.dad\/watch\.php\?id=\d+/i.test(originalCandidate) && r._orig && /dlhd\.dad\/watch\.php\?id=\d+/i.test(r._orig)) {
                                    originalCandidate = r._orig;
                                }
                                // (rimosso log dettaglio CHECK)
                                // Solo se l'originale sembra un link dlhd.dad/watch.php?id=...
                                if (!/dlhd\.dad\/watch\.php\?id=\d+/i.test(originalCandidate)) continue;
                                const proxyUrl = cfPrefix + originalCandidate;
                                // Evita duplicati se già presente
                                if (enriched.some(e => e.url === proxyUrl)) continue;
                                // Titolo: aggiungi 🔄 attaccato alla bandiera (senza spazio) mantenendo resto identico
                                let cfTitle = r.title;
                                if (cfTitle.startsWith('🇮🇹 ') && !cfTitle.startsWith('🇮🇹🔄')) {
                                    cfTitle = '🇮🇹🔄' + cfTitle.slice('🇮🇹'.length); // rimuove lo spazio dopo bandiera sostituendo con 🔄
                                    cfTitle = cfTitle.replace('🇮🇹🔄 ', '🇮🇹🔄 '); // garantisce un singolo spazio dopo la sequenza
                                } else if (cfTitle.startsWith('🇮🇹') && !cfTitle.startsWith('🇮🇹🔄')) {
                                    // Caso già senza spazio
                                    cfTitle = cfTitle.replace(/^🇮🇹/, '🇮🇹🔄');
                                }
                                enriched.push({ url: proxyUrl, title: cfTitle });
                            } catch { }
                        }
                        for (const r of enriched) streams.push(r);
                        // Append leftover entries (beyond CAP) as direct FAST (no extractor) to still expose them
                        if (extraFast.length) {
                            const leftoversToShow = CAP === 1 ? extraFast.slice(0, 1) : extraFast;
                            let appended = 0;
                            for (const e of leftoversToShow) {
                                if (!e || !e.url) continue;
                                let t = (e.title || 'Stream').trim();
                                if (!t) t = 'Stream';
                                t = t.replace(/^\s*\[(FAST|Player Esterno)\]\s*/i, '').trim();
                                if (!/^\[(Strd|RB77|SPSO|P🐽D|🌍dTV)\b/.test(t)) t = `[Player Esterno] ${t}`;
                                streams.push({ url: e.url, title: t });
                                appended++;
                            }
                            debugLog(`[DynamicStreams][EXTRACTOR] appended ${appended}/${extraFast.length} leftover direct streams (CAP=${CAP}) con etichetta condizionale 'Player Esterno'`);
                        }
                        debugLog(`[DynamicStreams][EXTRACTOR] Resolved ${resolved.length}/${entries.length} streams in ${Date.now() - startDyn}ms (conc=${CONCURRENCY})`);
                        // Filtro minimale senza MFP: rimuovi solo gli URL diretti dlhd.dad (duplicati CF restano)
                        if (!(mfpUrl && mfpPsw)) {
                            const beforeExt = streams.length;
                            for (let i = streams.length - 1; i >= 0; i--) {
                                if (/^https?:\/\/dlhd\.dad\/watch\.php\?id=\d+/i.test(streams[i].url)) streams.splice(i, 1);
                            }
                            if (beforeExt !== streams.length) debugLog(`[DynamicStreams][EXTRACTOR][NO_MFP] rimossi ${beforeExt - streams.length} dlhd.dad, rimasti=${streams.length}`);
                        }
                        dynamicHandled = true;
                    } else if ((channel as any)._dynamic) {
                        // Dynamic channel ma senza dynamicDUrls -> placeholder stream
                        streams.push({ url: (channel as any).placeholderVideo || (channel as any).logo || (channel as any).poster || '', title: 'Nessuno Stream' });
                        dynamicHandled = true;
                    } else {
                        // staticUrlF: Direct for non-dynamic
                        // pdUrlF: nuovo flusso provider [PD] (derivato da playlist) da mostrare sempre se presente
                        if ((channel as any).pdUrlF) {
                            try {
                                const pdUrl = (channel as any).pdUrlF;
                                if (pdUrl && !streams.some(s => s.url === pdUrl)) {
                                    // Inserisci il flusso PD sempre in prima posizione
                                    streams.unshift({
                                        url: pdUrl,
                                        title: `[P🐽D] ${channel.name}`
                                    });
                                    debugLog(`Aggiunto pdUrlF Direct: ${pdUrl}`);
                                }
                            } catch (e) {
                                debugLog('Errore aggiunta pdUrlF', (e as any)?.message || e);
                            }
                        }
                        if ((channel as any).staticUrlF) {
                            const originalF = (channel as any).staticUrlF;
                            const nameLower = (channel.name || '').toLowerCase().trim();
                            const raiMpdSet = new Set(['rai 1', 'rai 2', 'rai 3']); // Solo questi devono passare da proxy MPD
                            // Altri canali RAI (4,5,Movie,Premium, ecc.) restano DIRECT (niente proxy HLS come richiesto)
                            let finalFUrl = originalF;
                            if (mfpUrl && mfpPsw && raiMpdSet.has(nameLower)) {
                                if (!originalF.startsWith(mfpUrl)) {
                                    finalFUrl = `${mfpUrl}/proxy/mpd/manifest.m3u8?api_password=${encodeURIComponent(mfpPsw)}&d=${encodeURIComponent(originalF)}`;
                                }
                            }
                            streams.push({
                                url: finalFUrl,
                                title: `[🌍dTV] ${channel.name} [ITA]`
                            });
                            debugLog(`Aggiunto staticUrlF ${finalFUrl === originalF ? 'Direct' : 'Proxy(MPD)'}: ${finalFUrl}`);
                        }
                    }

                    // staticUrl (solo se enableMpd è attivo)
                    if ((channel as any).staticUrl && mpdEnabled) {
                        console.log(`🔧 [staticUrl] Raw URL: ${(channel as any).staticUrl}`);
                        const decodedUrl = decodeStaticUrl((channel as any).staticUrl);
                        console.log(`🔧 [staticUrl] Decoded URL: ${decodedUrl}`);
                        console.log(`🔧 [staticUrl] mfpUrl: ${mfpUrl}`);
                        console.log(`🔧 [staticUrl] mfpPsw: ${mfpPsw ? '***' : 'NOT SET'}`);

                        if (mfpUrl && mfpPsw) {
                            // Parse l'URL decodificato per separare l'URL base dai parametri
                            const urlParts = decodedUrl.split('&');
                            const baseUrl = urlParts[0]; // Primo elemento è l'URL base
                            const additionalParams = urlParts.slice(1); // Resto sono i parametri aggiuntivi

                            // Costruisci l'URL del proxy con l'URL base nel parametro d
                            let proxyUrl = `${mfpUrl}/proxy/mpd/manifest.m3u8?api_password=${encodeURIComponent(mfpPsw)}&d=${encodeURIComponent(baseUrl)}`;

                            // Aggiungi i parametri aggiuntivi (key_id, key, etc.) direttamente all'URL del proxy
                            for (const param of additionalParams) {
                                if (param) {
                                    proxyUrl += `&${param}`;
                                }
                            }

                            streams.push({
                                url: proxyUrl,
                                title: `[📺HD] ${channel.name} [ITA]`
                            });
                            debugLog(`Aggiunto staticUrl Proxy (MFP): ${proxyUrl}`);
                        } else {
                            // Richiesta: non mostrare stream senza proxy (titolo con [❌Proxy]) quando mancano credenziali MFP
                            debugLog(`(NASCONDI) staticUrl Direct senza MFP: ${decodedUrl}`);
                        }
                    }
                    // staticUrl2 (solo se enableMpd è attivo)
                    if ((channel as any).staticUrl2 && mpdEnabled) {
                        console.log(`🔧 [staticUrl2] Raw URL: ${(channel as any).staticUrl2}`);
                        const decodedUrl = decodeStaticUrl((channel as any).staticUrl2);
                        console.log(`🔧 [staticUrl2] Decoded URL: ${decodedUrl}`);
                        console.log(`🔧 [staticUrl2] mfpUrl: ${mfpUrl}`);
                        console.log(`🔧 [staticUrl2] mfpPsw: ${mfpPsw ? '***' : 'NOT SET'}`);

                        if (mfpUrl && mfpPsw) {
                            // Parse l'URL decodificato per separare l'URL base dai parametri
                            const urlParts = decodedUrl.split('&');
                            const baseUrl = urlParts[0]; // Primo elemento è l'URL base
                            const additionalParams = urlParts.slice(1); // Resto sono i parametri aggiuntivi

                            // Costruisci l'URL del proxy con l'URL base nel parametro d
                            let proxyUrl = `${mfpUrl}/proxy/mpd/manifest.m3u8?api_password=${encodeURIComponent(mfpPsw)}&d=${encodeURIComponent(baseUrl)}`;

                            // Aggiungi i parametri aggiuntivi (key_id, key, etc.) direttamente all'URL del proxy
                            for (const param of additionalParams) {
                                if (param) {
                                    proxyUrl += `&${param}`;
                                }
                            }

                            streams.push({
                                url: proxyUrl,
                                title: `[📽️] ${channel.name} [ITA]`
                            });
                            debugLog(`Aggiunto staticUrl2 Proxy (MFP): ${proxyUrl}`);
                        } else {
                            // Richiesta: nascondere versione direct senza MFP
                            debugLog(`(NASCONDI) staticUrl2 Direct senza MFP: ${decodedUrl}`);
                        }
                    }

                    // staticUrlMpd (sempre attivo se presente, non dipende da enableMpd)
                    if ((channel as any).staticUrlMpd) {
                        console.log(`🔧 [staticUrlMpd] Raw URL: ${(channel as any).staticUrlMpd}`);
                        const decodedUrl = decodeStaticUrl((channel as any).staticUrlMpd);
                        console.log(`🔧 [staticUrlMpd] Decoded URL: ${decodedUrl}`);
                        console.log(`🔧 [staticUrlMpd] mfpUrl: ${mfpUrl}`);
                        console.log(`🔧 [staticUrlMpd] mfpPsw: ${mfpPsw ? '***' : 'NOT SET'}`);

                        if (mfpUrl && mfpPsw) {
                            // Parse l'URL decodificato per separare l'URL base dai parametri
                            const urlParts = decodedUrl.split('&');
                            const baseUrl = urlParts[0]; // Primo elemento è l'URL base
                            const additionalParams = urlParts.slice(1); // Resto sono i parametri aggiuntivi

                            // Costruisci l'URL del proxy con l'URL base nel parametro d
                            let proxyUrl = `${mfpUrl}/proxy/mpd/manifest.m3u8?api_password=${encodeURIComponent(mfpPsw)}&d=${encodeURIComponent(baseUrl)}`;

                            // Aggiungi i parametri aggiuntivi (key_id, key, etc.) direttamente all'URL del proxy
                            for (const param of additionalParams) {
                                if (param) {
                                    proxyUrl += `&${param}`;
                                }
                            }

                            streams.push({
                                url: proxyUrl,
                                title: `[🎬MPD] ${channel.name} [ITA]`
                            });
                            debugLog(`Aggiunto staticUrlMpd Proxy (MFP): ${proxyUrl}`);
                        } else {
                            // Richiesta: nascondere versione direct senza MFP
                            debugLog(`(NASCONDI) staticUrlMpd Direct senza MFP: ${decodedUrl}`);
                        }
                    }

                    // staticUrlD / staticUrlD_CF
                    // Richiesta: i canali D_CF devono essere SEMPRE visibili anche senza MFP (perché già proxy CF pronto)
                    if ((channel as any).staticUrlD_CF) {
                        try {
                            const cfUrl = (channel as any).staticUrlD_CF;
                            streams.push({ url: cfUrl, title: `[🌐D_CF] ${channel.name} [ITA]` });
                            debugLog(`Aggiunto staticUrlD_CF (sempre visibile) ${mfpUrl && mfpPsw ? '(con MFP)' : '(senza MFP)'}`);
                        } catch (e) {
                            debugLog(`Errore gestione staticUrlD_CF: ${e}`);
                        }
                    }
                    // La versione D classica resta condizionata alla presenza MFP (altrimenti occultata come prima)
                    if ((channel as any).staticUrlD) {
                        if (mfpUrl && mfpPsw) {
                            // Nuova logica: chiama extractor/video con redirect_stream=false, poi costruisci il link proxy/hls/manifest.m3u8
                            const daddyApiBase = `${mfpUrl}/extractor/video?host=DLHD&redirect_stream=false&api_password=${encodeURIComponent(mfpPsw)}&d=${encodeURIComponent((channel as any).staticUrlD)}`;
                            try {
                                const res = await fetch(daddyApiBase);
                                if (res.ok) {
                                    const data = await res.json();
                                    let finalUrl = data.mediaflow_proxy_url || `${mfpUrl}/proxy/hls/manifest.m3u8`;
                                    // Aggiungi i parametri di query se presenti
                                    if (data.query_params) {
                                        const params = new URLSearchParams();
                                        for (const [key, value] of Object.entries(data.query_params)) {
                                            if (value !== null) {
                                                params.append(key, String(value));
                                            }
                                        }
                                        finalUrl += (finalUrl.includes('?') ? '&' : '?') + params.toString();
                                    }
                                    // Aggiungi il parametro d per il destination_url
                                    if (data.destination_url) {
                                        const destParam = 'd=' + encodeURIComponent(data.destination_url);
                                        finalUrl += (finalUrl.includes('?') ? '&' : '?') + destParam;
                                    }
                                    // Aggiungi gli header come parametri h_
                                    if (data.request_headers) {
                                        for (const [key, value] of Object.entries(data.request_headers)) {
                                            if (value !== null) {
                                                const headerParam = `h_${key}=${encodeURIComponent(String(value))}`;
                                                finalUrl += '&' + headerParam;
                                            }
                                        }
                                    }
                                    streams.push({
                                        url: finalUrl,
                                        title: `[🌐D] ${channel.name} [ITA]`
                                    });
                                    debugLog(`Aggiunto staticUrlD Proxy (MFP, nuova logica): ${finalUrl}`);
                                } else {
                                    // Nothing returned; avoid adding extractor/video fallback
                                }
                            } catch (err) {
                                // Error; skip extractor/video fallback altogether
                            }
                        } else {
                            // Richiesta: nascondere versione direct senza MFP
                            debugLog(`(NASCONDI) staticUrlD Direct senza MFP: ${(channel as any).staticUrlD}`);
                        }
                    }
                    // === Freeshot (iniezione dopo D/D_CF e prima di daddy/spso/strd/rbtv) ===
                    try {
                        // Import lazy per evitare crash se modulo assente in build parziale
                        // const { resolveFreeshotForChannel } = await import('./extractors/freeshotRuntime');
                        const resolveFreeshotForChannel: any = null; // Disabled
                        let extraTexts: string[] | undefined;
                        try {
                            if ((channel as any).dynamicDUrls && Array.isArray((channel as any).dynamicDUrls)) {
                                extraTexts = (channel as any).dynamicDUrls
                                    .map((d: any) => d?.title || '')
                                    .filter((s: string) => !!s && typeof s === 'string');
                            }
                        } catch { }
                        // const fr = await resolveFreeshotForChannel({ id: (channel as any).id, name: (channel as any).name, epgChannelIds: (channel as any).epgChannelIds, extraTexts });
                        const fr: any = null; // Disabled
                        if (fr && fr.url && !fr.error) {
                            const freeName = (fr as any).displayName || (channel as any).name || 'Canale';
                            // Posizioniamo subito dopo eventuali D/D_CF: push ora e poi proseguono altri provider
                            streams.push({
                                url: fr.url,
                                title: `[🏟 Free] ${freeName} [ITA]`
                            });
                            debugLog(`Freeshot aggiunto per ${freeName}: ${fr.url}`);
                        } else if (fr && fr.error) {
                            debugLog(`Freeshot errore ${channel.name}: ${fr.error}`);
                        }
                    } catch (e) {
                        debugLog(`Freeshot import/fetch fallito: ${e}`);
                    }
                    // Vavoo
                    if (!dynamicHandled && (channel as any).name) {
                        // DEBUG LOGS
                        console.log('🔧 [VAVOO] DEBUG - channel.name:', (channel as any).name);
                        const baseName = (channel as any).name.replace(/\s*(\(\d+\)|\d+)$/, '').trim();
                        console.log('🔧 [VAVOO] DEBUG - baseName:', baseName);
                        const variant2 = `${baseName} (2)`;
                        const variantNum = `${baseName} 2`;
                        console.log('🔧 [VAVOO] DEBUG - variant2:', variant2);
                        console.log('🔧 [VAVOO] DEBUG - variantNum:', variantNum);
                        // --- VAVOO: cerca tutte le varianti .<lettera> per ogni nome in vavooNames (case-insensitive), sia originale che normalizzato ---
                        const vavooNamesArr = (channel as any).vavooNames || [channel.name];
                        // LOG RAW delle chiavi della cache
                        console.log('[VAVOO] CACHE KEYS RAW:', Array.from(vavooCache.links.keys()));
                        console.log(`[VAVOO] CERCA: vavooNamesArr =`, vavooNamesArr);
                        const allCacheKeys = Array.from(vavooCache.links.keys());
                        console.log(`[VAVOO] CACHE KEYS:`, allCacheKeys);
                        const foundVavooLinks: { url: string, key: string }[] = [];
                        for (const vavooName of vavooNamesArr) {
                            // Cerca con nome originale
                            console.log(`[VAVOO] CERCA (original): '${vavooName} .<lettera>'`);
                            const variantRegex = new RegExp(`^${vavooName} \.([a-zA-Z])$`, 'i');
                            for (const [key, value] of vavooCache.links.entries()) {
                                if (variantRegex.test(key)) {
                                    console.log(`[VAVOO] MATCH (original): chiave trovata '${key}' per vavooName '${vavooName}'`);
                                    const links = Array.isArray(value) ? value : [value];
                                    for (const url of links) {
                                        foundVavooLinks.push({ url, key });
                                        console.log(`[VAVOO] LINK trovato (original): ${url} (chiave: ${key})`);
                                    }
                                }
                            }
                            // Cerca anche con nome normalizzato (ma solo se diverso)
                            const vavooNameNorm = vavooName.toUpperCase().replace(/\s+/g, ' ').trim();
                            if (vavooNameNorm !== vavooName) {
                                console.log(`[VAVOO] CERCA (normalizzato): '${vavooNameNorm} .<lettera>'`);
                                const variantRegexNorm = new RegExp(`^${vavooNameNorm} \.([a-zA-Z])$`, 'i');
                                for (const [key, value] of vavooCache.links.entries()) {
                                    const keyNorm = key.toUpperCase().replace(/\s+/g, ' ').trim();
                                    if (variantRegexNorm.test(keyNorm)) {
                                        console.log(`[VAVOO] MATCH (normalizzato): chiave trovata '${key}' per vavooNameNorm '${vavooNameNorm}'`);
                                        const links = Array.isArray(value) ? value : [value];
                                        for (const url of links) {
                                            foundVavooLinks.push({ url, key });
                                            console.log(`[VAVOO] LINK trovato (normalizzato): ${url} (chiave: ${key})`);
                                        }
                                    }
                                }
                            }
                        }

                        // (RIMOSSO blocco test SPON static: test completato)
                        // Se trovi almeno un link, aggiungi tutti come stream separati numerati
                        if (foundVavooLinks.length > 0) {
                            // Converted to for-of for async support
                            for (let idx = 0; idx < foundVavooLinks.length; idx++) {
                                const { url, key } = foundVavooLinks[idx];
                                const streamTitle = `[✌️ V-${idx + 1}] ${channel.name} [ITA]`;
                                if (mfpUrl && mfpPsw) {
                                    const vavooProxyUrl = `${mfpUrl}/proxy/hls/manifest.m3u8?d=${encodeURIComponent(url)}&api_password=${encodeURIComponent(mfpPsw)}`;
                                    streams.push({
                                        title: streamTitle,
                                        url: vavooProxyUrl
                                    });
                                } else {
                                    // Richiesta: nascondere stream Vavoo direct senza MFP
                                }
                                vavooFoundUrls.push(url);
                                // For each found link, also prepare a clean variant labeled per index (➡️ V-1, V-2, ...)
                                const reqObj: any = (global as any).lastExpressRequest;
                                const clientIp = await getClientIpFromReq(reqObj);
                                const pClean = (async () => {
                                    vdbg('Variant clean resolve attempt', { index: idx + 1, url: url.substring(0, 140) });
                                    try {
                                        const clean = await resolveVavooCleanUrl(url, clientIp);
                                        if (clean && clean.url) {
                                            const title = `[🏠 V-${idx + 1}] ${channel.name} [ITA]`;
                                            const urlWithHeaders = clean.url + `#headers#` + Buffer.from(JSON.stringify(clean.headers)).toString('base64');
                                            vavooCleanPrepend[idx] = { title, url: urlWithHeaders };
                                        }
                                    } catch (err) {
                                        vdbg('Variant clean failed', { index: idx + 1, error: (err as any)?.message || err });
                                    }
                                })();
                                vavooCleanPromises.push(pClean);
                            }
                            console.log(`[VAVOO] RISULTATO: trovati ${foundVavooLinks.length} link, stream generati:`, streams.map(s => s.title));
                        } else {
                            // fallback: chiave esatta
                            const exact = vavooCache.links.get(channel.name);
                            if (exact) {
                                const links = Array.isArray(exact) ? exact : [exact];
                                // links.forEach((url, idx) => {
                                for (let idx = 0; idx < links.length; idx++) {
                                    const url = String(links[idx]);
                                    const streamTitle = `[✌️ V-${idx + 1}] ${channel.name} [ITA]`;
                                    if (mfpUrl && mfpPsw) {
                                        const vavooProxyUrl = `${mfpUrl}/proxy/hls/manifest.m3u8?d=${encodeURIComponent(url)}&api_password=${encodeURIComponent(mfpPsw)}`;
                                        streams.push({
                                            title: streamTitle,
                                            url: vavooProxyUrl
                                        });
                                    } else {
                                        // Richiesta: nascondere stream Vavoo direct senza MFP
                                    }
                                    vavooFoundUrls.push(url);
                                    // Prepare clean variant per index as well
                                    const reqObj: any = (global as any).lastExpressRequest;
                                    const clientIp = await getClientIpFromReq(reqObj);
                                    const pClean = (async () => {
                                        vdbg('Variant clean resolve attempt', { index: idx + 1, url: url.substring(0, 140) });
                                        try {
                                            const clean = await resolveVavooCleanUrl(url, clientIp);
                                            if (clean && clean.url) {
                                                const title = `[🏠 V-${idx + 1}] ${channel.name} [ITA]`;
                                                const urlWithHeaders = clean.url + `#headers#` + Buffer.from(JSON.stringify(clean.headers)).toString('base64');
                                                vavooCleanPrepend[idx] = { title, url: urlWithHeaders };
                                            }
                                        } catch (err) {
                                            vdbg('Variant clean failed', { index: idx + 1, error: (err as any)?.message || err });
                                        }
                                    })();
                                    vavooCleanPromises.push(pClean);
                                }
                                console.log(`[VAVOO] RISULTATO: fallback chiave esatta, trovati ${links.length} link, stream generati:`, streams.map(s => s.title));
                            } else {
                                console.log(`[VAVOO] RISULTATO: nessun link trovato per questo canale.`);
                            }
                        }
                    }

                    // Se già gestito come evento dinamico, salta Vavoo/TVTap e ritorna subito
                    if (dynamicHandled) {
                        // Se dynamicHandled è true, gli stream raccolti in 'streams' non sono ancora stati trasferiti in allStreams.
                        // Cerchiamo eventuale Freeshot appena aggiunto (titolo che inizia con [🏟 Free]) e lo mettiamo all'inizio (dopo eventuali D_CF/D se presenti).
                        try {
                            const freeshotIdx = streams.findIndex(s => /\[🏟\s*Free\]/i.test(s.title));
                            if (freeshotIdx > -1) {
                                const freeshotStream = streams.splice(freeshotIdx, 1)[0];
                                // Trova posizione dopo eventuali D_CF / D
                                let insertPos = 0;
                                for (let i = 0; i < streams.length; i++) {
                                    if (/\[🌐D_CF\]/.test(streams[i].title) || /\[🌐D\]/.test(streams[i].title)) {
                                        insertPos = i + 1; // dopo l'ultimo D/D_CF
                                    }
                                }
                                streams.splice(insertPos, 0, freeshotStream);
                            }
                        } catch { }
                        // === SPON (sportzonline) injection (always-on, no placeholders / no time gating) ===
                        try {
                            const eventName = (channel as any).name || '';
                            if (!eventName) {
                                // nothing
                            } else {
                                // const { fetchSponSchedule, matchRowsForEvent, debugExtractTeams } = await import('./extractors/sponSchedule');
                                // const { extractSportzonlineStream } = await import('./extractors/sportsonline');
                                // const schedule = await fetchSponSchedule(false).catch(() => [] as any[]);
                                const schedule: any[] = []; // Disabled
                                const debugExtractTeams = (s: any) => ({ team1: '', team2: '', raw: '' });
                                const matchRowsForEvent = (a: any, b: any): any[] => [];
                                if (!Array.isArray(schedule) || !schedule.length) {
                                    debugLog(`[SPON][DEBUG] schedule empty/invalid for '${eventName}'`);
                                } else {
                                    try { const dbg = debugExtractTeams(eventName); debugLog(`[SPON][DEBUG] parsed teams t1='${dbg.team1}' t2='${dbg.team2}' raw='${dbg.raw}'`); } catch { }
                                    const matched = matchRowsForEvent({ name: eventName }, schedule as any) || [];
                                    if (!matched.length) {
                                        debugLog(`[SPON][DEBUG] matched=0 for '${eventName}'`);
                                    } else {
                                        // Calcolo solo per futureTag (no gating)
                                        let eventStart: Date | null = null; let futureTag = '';
                                        try {
                                            const nowDate = new Date();
                                            const weekdayMap: Record<string, number> = { 'SUNDAY': 0, 'MONDAY': 1, 'TUESDAY': 2, 'WEDNESDAY': 3, 'THURSDAY': 4, 'FRIDAY': 5, 'SATURDAY': 6 };
                                            const target = weekdayMap[matched[0].day.toUpperCase()] ?? nowDate.getDay();
                                            const base = new Date(nowDate);
                                            const diff = (target - base.getDay() + 7) % 7; base.setDate(base.getDate() + diff);
                                            const [hh, mm] = matched[0].time.split(':').map((n: string) => parseInt(n, 10));
                                            base.setHours(hh, mm, 0, 0); eventStart = base;
                                            const deltaMs = eventStart.getTime() - Date.now();
                                            if (deltaMs > 0) futureTag = ` (Inizia alle ${matched[0].time})`;
                                        } catch { }
                                        const mfpUrl = (config.mediaFlowProxyUrl || process.env.MFP_URL || process.env.MEDIAFLOW_PROXY_URL || '').toString().trim();
                                        const mfpPsw = (config.mediaFlowProxyPassword || process.env.MFP_PASSWORD || process.env.MEDIAFLOW_PROXY_PASSWORD || process.env.MFP_PSW || '').toString().trim();
                                        if (!mfpUrl || !mfpPsw) {
                                            debugLog(`[SPON] MFP non configurato -> salto estrazione per '${eventName}'`);
                                        } else {
                                            const seen = new Set<string>();
                                            const collected: Stream[] = [];
                                            for (const row of matched.slice(0, 12)) {
                                                const tag = row.channelCode.toUpperCase();
                                                try {
                                                    debugLog(`[SPON][ROW] extracting ${tag} ${row.url}`);
                                                    // const res = await extractSportzonlineStream(row.url).catch((e: any) => { debugLog(`[SPON][ROW] extractor error ${tag} ${(e?.message) || e}`); return null; });
                                                    const res: any = null; // Disabled
                                                    if (!res || !res.url) { debugLog(`[SPON][ROW] no stream ${tag}`); continue; }
                                                    if (seen.has(res.url)) { debugLog(`[SPON][ROW] dup skip ${tag}`); continue; }
                                                    seen.add(res.url);
                                                    const italianFlag = /^(hd7|hd8)$/i.test(row.channelCode) ? ' 🇮🇹' : '';
                                                    const referer = encodeURIComponent(res.headers?.Referer || res.headers?.referer || '');
                                                    const ua = encodeURIComponent(res.headers?.['User-Agent'] || res.headers?.['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36');
                                                    const wrapped = `${mfpUrl.replace(/\/$/, '')}/proxy/hls/manifest.m3u8?api_password=${encodeURIComponent(mfpPsw)}&d=${encodeURIComponent(res.url)}${referer ? `&h_Referer=${referer}` : ''}${ua ? `&h_User-Agent=${ua}` : ''}`;
                                                    collected.push({ url: wrapped, title: `[SPON${italianFlag}] ${eventName}${futureTag} (${tag})` } as any);
                                                    debugLog(`[SPON][ROW] success ${tag}`);
                                                } catch (err: any) { debugLog(`[SPON][ROW] unexpected error ${tag} ${(err?.message) || err}`); }
                                            }
                                            if (collected.length) {
                                                collected.sort((a, b) => {
                                                    const aKey = /(HD7\)|HD8\))/i.test(a.title || '') ? 0 : /\(HD7\)|\(HD8\)/i.test(a.title || '') ? 0 : /\(HD7\)/i.test(a.title || '') ? 0 : /\(HD8\)/i.test(a.title || '') ? 0 : 1;
                                                    const bKey = /(HD7\)|HD8\))/i.test(b.title || '') ? 0 : /\(HD7\)|\(HD8\)/i.test(b.title || '') ? 0 : /\(HD7\)/i.test(b.title || '') ? 0 : /\(HD8\)/i.test(b.title || '') ? 0 : 1;
                                                    if (aKey !== bKey) return aKey - bKey; return (a.title || '').localeCompare(b.title || '');
                                                });
                                                let insertAt = streams.length;
                                                // 1. Prefer position immediately before first SPSO
                                                for (let i = 0; i < streams.length; i++) { if (/\[SPSO\]/i.test(streams[i].title)) { insertAt = i; break; } }
                                                if (insertAt === streams.length) {
                                                    // 2. No SPSO: place right AFTER last Daddy (with 🇮🇹 or rotating arrows emoji) if any
                                                    const rotatingRegex = /[↻🔄🔁⟳🌀]/;
                                                    for (let i = streams.length - 1; i >= 0; i--) {
                                                        const t = streams[i].title || '';
                                                        if (/daddy/i.test(t) && (t.includes('🇮🇹') || rotatingRegex.test(t))) { insertAt = i + 1; break; }
                                                    }
                                                }
                                                const existing = new Set(streams.map(s => s.url));
                                                const finalIns = collected.filter(s => s.url && !existing.has(s.url));
                                                if (finalIns.length) { streams.splice(insertAt, 0, ...(finalIns as any)); debugLog(`[SPON] Injected ${finalIns.length} SPON streams (always-on) per '${eventName}'`); }
                                                else debugLog(`[SPON] Nessun nuovo stream (duplicati) per '${eventName}'`);
                                            } else {
                                                debugLog(`[SPON] Nessun stream estratto per '${eventName}' (no placeholder)`);
                                            }
                                        }
                                    }
                                }
                            }
                        } catch (e) { debugLog('[SPON] injection error', e); }
                        const allowVavooClean = true; // simplified: always allow clean Vavoo variant
                        for (const s of streams) {
                            // Skip any remaining MFP extractor links entirely
                            if (/\/extractor\/video\?/i.test(s.url)) {
                                debugLog('[DynamicStreams] Skipping extractor/video URL in dynamicHandled emit:', s.url);
                                continue;
                            }
                            // Support special marker '#headers#<b64json>' to attach headers properly
                            const marker = '#headers#';
                            if (s.url.includes(marker)) {
                                const [pureUrl, b64] = s.url.split(marker);
                                let hdrs: Record<string, string> | undefined;
                                try { hdrs = JSON.parse(Buffer.from(b64, 'base64').toString('utf8')); } catch { }
                                const isVavooClean = !!hdrs && hdrs['Referer'] === 'https://vavoo.to/' && hdrs['User-Agent'] === DEFAULT_VAVOO_UA;
                                if (isVavooClean && !allowVavooClean) { continue; }
                                allStreams.push({ name: isVavooClean ? 'Vavoo🔓' : 'Live 🔴', title: s.title, url: pureUrl, behaviorHints: { notWebReady: true, headers: hdrs || {}, proxyHeaders: hdrs || {}, proxyUseFallback: true } as any });
                            } else {
                                // Fallback: if this looks like a clean Vavoo sunshine URL and title starts with a variant tag, attach default headers
                                const looksVavoo = /\b(sunshine|hls\/index\.m3u8)\b/.test(s.url) && !/\bproxy\/hls\//.test(s.url);
                                const variantTitle = /^\s*\[?\s*(➡️|🏠|✌️)\s*V/i.test(s.title);
                                if (variantTitle && looksVavoo) {
                                    const hdrs = { 'User-Agent': DEFAULT_VAVOO_UA, 'Referer': 'https://vavoo.to/' } as Record<string, string>;
                                    if (!allowVavooClean) { continue; }
                                    allStreams.push({ name: 'Vavoo🔓', title: s.title, url: s.url, behaviorHints: { notWebReady: true, headers: hdrs, proxyHeaders: hdrs, proxyUseFallback: true } as any });
                                } else {
                                    allStreams.push({ name: 'Live 🔴', title: s.title, url: s.url });
                                }
                            }
                        }
                        console.log(`✅ Returning ${allStreams.length} dynamic event streams`);
                        return { streams: allStreams };
                    }
                    // --- TVTAP: cerca usando vavooNames ---
                    const vavooNamesArr = (channel as any).vavooNames || [channel.name];
                    console.log(`[TVTap] Cerco canale con vavooNames:`, vavooNamesArr);
                    // tvtapProxyEnabled: TRUE = NO PROXY (mostra 🔓), FALSE = usa proxy se possibile
                    const tvtapNoProxy = !!config.tvtapProxyEnabled;

                    // Prova ogni nome nei vavooNames
                    for (const vavooName of vavooNamesArr) {
                        try {
                            console.log(`[TVTap] Provo con nome: ${vavooName}`);

                            const tvtapUrl = await new Promise<string | null>((resolve) => {
                                const timeout = setTimeout(() => {
                                    console.log(`[TVTap] Timeout per canale: ${vavooName}`);
                                    resolve(null);
                                }, 5000);

                                const options = {
                                    timeout: 5000,
                                    env: {
                                        ...process.env,
                                        PYTHONPATH: '/usr/local/lib/python3.9/site-packages'
                                    }
                                };

                                const pythonBin = process.env.PYTHON_BIN || 'python3';
                                execFile(pythonBin, [path.join(__dirname, '../tvtap_resolver.py'), vavooName], options, (error: Error | null, stdout: string, stderr: string) => {
                                    clearTimeout(timeout);

                                    if (error) {
                                        console.error(`[TVTap] Error for ${vavooName}:`, error.message);
                                        return resolve(null);
                                    }

                                    if (!stdout || stdout.trim() === '') {
                                        console.log(`[TVTap] No output for ${vavooName}`);
                                        return resolve(null);
                                    }

                                    const result = stdout.trim();
                                    if (result === 'NOT_FOUND' || result === 'NO_CHANNELS' || result === 'NO_ID' || result === 'STREAM_FAIL') {
                                        console.log(`[TVTap] Channel not found: ${vavooName} (${result})`);
                                        return resolve(null);
                                    }

                                    if (result.startsWith('http')) {
                                        console.log(`[TVTap] Trovato stream per ${vavooName}: ${result}`);
                                        resolve(result);
                                    } else {
                                        console.log(`[TVTap] Output non valido per ${vavooName}: ${result}`);
                                        resolve(null);
                                    }
                                });
                            });

                            if (tvtapUrl) {
                                const baseTitle = `[📺 TvTap SD] ${channel.name} [ITA]`;
                                if (tvtapNoProxy || !(mfpUrl && mfpPsw)) {
                                    // NO Proxy mode scelto (checkbox ON) oppure mancano credenziali -> link diretto con icona 🔓 senza [❌Proxy]
                                    streams.push({
                                        title: `🔓 ${baseTitle}`,
                                        url: tvtapUrl
                                    });
                                    console.log(`[TVTap] DIRECT (NO PROXY mode=${tvtapNoProxy}) per ${channel.name} tramite ${vavooName}`);
                                } else {
                                    // Checkbox OFF e credenziali presenti -> usa proxy
                                    const tvtapProxyUrl = `${mfpUrl}/proxy/hls/manifest.m3u8?d=${encodeURIComponent(tvtapUrl)}&api_password=${encodeURIComponent(mfpPsw)}`;
                                    streams.push({
                                        title: baseTitle,
                                        url: tvtapProxyUrl
                                    });
                                    console.log(`[TVTap] PROXY stream per ${channel.name} tramite ${vavooName}`);
                                }
                                break; // Esci dal loop se trovi un risultato
                            }
                        } catch (error) {
                            console.error(`[TVTap] Errore per vavooName ${vavooName}:`, error);
                        }
                    }

                    if (streams.length === 0) {
                        console.log(`[TVTap] RISULTATO: nessun stream trovato per ${channel.name}`);
                    }

                    // ============ END INTEGRATION SECTIONS ============

                    // Attendi eventuali risoluzioni clean Vavoo prima di restituire
                    if (vavooCleanPromises.length) {
                        try { await Promise.allSettled(vavooCleanPromises); } catch { }
                        // Prepend clean Vavoo variants in order (V-1 first)
                        let inserted = 0;
                        vdbg('Clean prepend result', { inserted, totalVariants: vavooCleanPrepend.length });
                        for (let i = vavooCleanPrepend.length - 1; i >= 0; i--) {
                            const entry = vavooCleanPrepend[i];
                            if (entry) { streams.unshift(entry); inserted++; }
                        }
                        // If none resolved clean, add numbered fallbacks with default headers for visibility
                        if (inserted === 0 && vavooFoundUrls.length > 0) {
                            for (let i = vavooFoundUrls.length - 1; i >= 0; i--) {
                                const u = vavooFoundUrls[i];
                                const hdrs = { 'User-Agent': DEFAULT_VAVOO_UA, 'Referer': 'https://vavoo.to/' } as Record<string, string>;
                                const urlWithHeaders = u + `#headers#` + Buffer.from(JSON.stringify(hdrs)).toString('base64');
                                streams.unshift({ title: `[🏠 V-${i + 1}] ${channel.name} [ITA]`, url: urlWithHeaders });
                            }
                        }
                    }
                    // Dopo aver popolato streams (nella logica TV):
                    for (const s of streams) {
                        // Drop any extractor/video links
                        if (/\/extractor\/video\?/i.test(s.url)) {
                            debugLog('[Streams] Skipping extractor/video URL in final emit:', s.url);
                            continue;
                        }
                        const allowVavooClean = true;
                        const marker = '#headers#';
                        if (s.url.includes(marker)) {
                            const [pureUrl, b64] = s.url.split(marker);
                            let hdrs: Record<string, string> | undefined;
                            try { hdrs = JSON.parse(Buffer.from(b64, 'base64').toString('utf8')); } catch { }
                            const isVavooClean = !!hdrs && hdrs['Referer'] === 'https://vavoo.to/' && hdrs['User-Agent'] === DEFAULT_VAVOO_UA;
                            if (isVavooClean && !allowVavooClean) { continue; }
                            allStreams.push({ name: isVavooClean ? 'Vavoo🔓' : 'Live 🔴', title: s.title, url: pureUrl, behaviorHints: { notWebReady: true, headers: hdrs || {}, proxyHeaders: hdrs || {}, proxyUseFallback: true } as any });
                        } else {
                            const looksVavoo = /\b(sunshine|hls\/index\.m3u8)\b/.test(s.url) && !/\bproxy\/hls\//.test(s.url);
                            const variantTitle = /^\s*\[?\s*(➡️|🏠|✌️)\s*V/i.test(s.title);
                            if (variantTitle && looksVavoo) {
                                const hdrs = { 'User-Agent': DEFAULT_VAVOO_UA, 'Referer': 'https://vavoo.to/' } as Record<string, string>;
                                if (!allowVavooClean) { continue; }
                                allStreams.push({ name: 'Vavoo🔓', title: s.title, url: s.url, behaviorHints: { notWebReady: true, headers: hdrs, proxyHeaders: hdrs, proxyUseFallback: true } as any });
                            } else {
                                allStreams.push({ name: 'Live 🔴', title: s.title, url: s.url });
                            }
                        }
                    }

                    // 5. AGGIUNGI STREAM ALTERNATIVI/FALLBACK per canali specifici
                    // RIMOSSO: Blocco che aggiunge fallback stream alternativi per canali Sky (skyFallbackUrls) se finalStreams.length < 3
                    // return { streams: finalStreamsWithRealUrls };
                }

                // === LOGICA ANIME/FILM (Refactored: VixSrc Only) ===
                if (id.startsWith('tt') || id.startsWith('tmdb:') || id.startsWith('kitsu:') || id.startsWith('mal:')) {
                    const vixsrcEnabled = (() => {
                        try {
                            const cfg3 = { ...configCache } as AddonConfig;
                            if (cfg3.disableVixsrc === true) return false;
                        } catch { }
                        return true;
                    })();

                    if (vixsrcEnabled) {
                        try {
                            const finalConfig: ExtractorConfig = {
                                tmdbApiKey: config.tmdbApiKey || process.env.TMDB_API_KEY || '40a9faa1f6741afb2c0c40238d85f8d0',
                                mfpUrl: config.mediaFlowProxyUrl || process.env.MFP_URL,
                                mfpPsw: config.mediaFlowProxyPassword || process.env.MFP_PSW,

                                vixDual: !!(config as any)?.vixDual,
                                vixDirect: (config as any)?.vixDirect === true,
                                vixDirectFhd: (config as any)?.vixDirectFhd === true,
                                vixProxy: (config as any)?.vixProxy === true,
                                vixProxyFhd: (config as any)?.vixProxyFhd === true,
                                addonBase: (config as any)?.addonBase || (() => {
                                    try {
                                        const proto = (process.env.EXTERNAL_PROTOCOL || 'https');
                                        const host = (process.env.EXTERNAL_HOST || process.env.HOST || process.env.VERCEL_URL || '').replace(/\/$/, '');
                                        if (host) return `${proto}://${host}`;
                                        return '';
                                    } catch { return ''; }
                                })()
                            };

                            console.log('[VixSrc] Fetching streams for:', id);
                            const res: VixCloudStreamInfo[] | null = await getStreamContent(id, type, finalConfig);

                            if (res) {
                                // === LOCAL STREAM UNIFICATION FOR VIXSRC ===
                                let canonicalVixBase: string | null = null;
                                // 1. Find canonical base title
                                for (const st of res) {
                                    const first = (st.name || '').toString().split('\n')[0];
                                    if (first && !/Synthetic FHD|Proxy FHD/i.test(first)) {
                                        canonicalVixBase = first
                                            .replace(/^\s*🎬\s*/, '')
                                            .replace(/\[?(ITA|SUB)\]?/ig, '')
                                            .replace(/🔒|🔓FHD?|🔓/g, '')
                                            .replace(/\s*•\s*/g, ' ')
                                            .replace(/\s{2,}/g, ' ')
                                            .trim();
                                        if (canonicalVixBase) break;
                                    }
                                }
                                if (!canonicalVixBase) {
                                    for (const st of res) {
                                        if ((st as any).originalName) { canonicalVixBase = (st as any).originalName; break; }
                                    }
                                }

                                for (const st of res) {
                                    if (!st.streamUrl) continue;

                                    // Title Cleanup
                                    let baseLine = (st.name || '').toString().split('\n')[0] || 'VixSrc';
                                    baseLine = baseLine.replace(/^\s*🎬\s*/, '')
                                        .replace(/^\s*\[[^\]]+\]\s*/, '').trim()
                                        .replace(/\s*[•▪]\s*\[?(ITA|SUB)\]?/ig, '')
                                        .replace(/\s*\b(ITA|SUB)\b/ig, '')
                                        .replace(/\s*•\s*\[SUB ITA\]/ig, '')
                                        .replace(/\s{2,}/g, ' ').trim();

                                    const isSynthetic = !!st.isSyntheticFhd;
                                    if (/^(Synthetic FHD|Proxy FHD)$/i.test(baseLine)) {
                                        if (canonicalVixBase) baseLine = canonicalVixBase;
                                        else if ((st as any).originalName) baseLine = (st as any).originalName;
                                    }

                                    baseLine = baseLine
                                        .replace(/\[?(ITA|SUB)\]?/ig, '')
                                        .replace(/🔒|🔓FHD?|🔓/g, '')
                                        .replace(/\s*•\s*/g, ' ')
                                        .replace(/\s{2,}/g, ' ')
                                        .replace(/\[ITA\]/ig, '')
                                        .replace(/\[SUB\]/ig, '')
                                        .trim();

                                    const isSub = /\bsub\b|\[sub\]/i.test((st.name || ''));
                                    const proxyOn = /\/proxy\//i.test(st.streamUrl) || /api_password=/i.test(st.streamUrl) || !!(st as any)?.behaviorHints?.proxyHeaders;

                                    // Formatting output lines
                                    const outLines: string[] = [];
                                    outLines.push(`🎬 ${baseLine}`);
                                    outLines.push(`🗣 [${isSub ? 'SUB' : 'ITA'}]`);

                                    const fmtBytes = (n: number) => {
                                        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
                                        let v = n; let u = 0; while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
                                        return `${v.toFixed(v >= 10 || u === 0 ? 0 : 1)} ${units[u]}`;
                                    };
                                    const sizeLabel = (typeof st.sizeBytes === 'number' && st.sizeBytes > 0) ? fmtBytes(st.sizeBytes) : '';
                                    if (sizeLabel) outLines.push(`💾 ${sizeLabel}`);
                                    outLines.push(`🌐 Proxy (${proxyOn ? 'ON' : 'OFF'})`);

                                    const unifiedTitle = outLines.join('\n');

                                    // Binge Group Logic
                                    let variant = 'base';
                                    const isFhdVariant = isSynthetic || /FHD/i.test(st.name || '') || /1080p/i.test(st.name || '');
                                    if (isFhdVariant) variant = proxyOn ? 'proxyFHD' : 'directFHD';
                                    else variant = proxyOn ? 'proxy' : 'direct';
                                    const bingeGroup = `vixsrc-${variant}`;

                                    allStreams.push({
                                        name: providerLabel('vixsrc', isSynthetic),
                                        title: unifiedTitle,
                                        url: st.streamUrl,
                                        behaviorHints: {
                                            notWebReady: true,
                                            headers: { Referer: st.referer },
                                            bingeGroup: bingeGroup
                                        } as any,
                                        originalName: (st as any).originalName
                                    });
                                }
                            }
                        } catch (error) {
                            console.error('[VixSrc] Execution error:', error);
                        }
                    }
                }
                console.log(`✅ Total streams returned: ${allStreams.length}`);
                return { streams: allStreams };
            } catch (error) {
                console.error('Stream extraction failed:', error);
                return { streams: [] };
            }
        }
    );

    return builder;
}

// Server Express
const app = express();
// Trust proxy chain so req.ip / req.ips use X-Forwarded-For correctly when behind a proxy/CDN
try { (app as any).set('trust proxy', true); } catch { }

// PRIORITY: Configure routes must be first to avoid conflicts with global router
// Explicit '/configure' route (no config prefix) -> redirects to root or renders default
app.get('/configure', (_req: Request, res: Response) => {
    // Redirect to root which already serves the landing page (configure page)
    res.redirect('/');
});

// Single, minimal Configure handler: '/{config}/configure'
app.get(/^\/(.+)\/configure\/?$/, (req: Request, res: Response) => {
    try {
        const base = loadCustomConfig();
        // First capture group includes everything between the first slash and '/configure'
        const between = (req.params as any)[0] as string;
        const rawQueryCfg = typeof req.query.config === 'string' ? (req.query.config as string) : undefined;
        const cfgFromUrl = between ? parseConfigFromArgs(between) : (rawQueryCfg ? parseConfigFromArgs(rawQueryCfg) : {});
        const manifestWithDefaults: any = { ...base };
        if (Array.isArray(manifestWithDefaults.config)) {
            manifestWithDefaults.config = manifestWithDefaults.config.map((c: any) => {
                const val = (cfgFromUrl as any)?.[c?.key];
                if (typeof val !== 'undefined') return { ...c, default: c.type === 'checkbox' ? !!val : String(val) };
                return c;
            });
        }
        res.setHeader('Content-Type', 'text/html');
        return res.send(landingTemplate(manifestWithDefaults));
    } catch (e) {
        console.error('âŒ Configure (regex) error:', (e as any)?.message || e);
        const manifest = loadCustomConfig();
        res.setHeader('Content-Type', 'text/html');
        return res.send(landingTemplate(manifest));
    }
});


app.use('/public', express.static(path.join(__dirname, '..', 'public')));

// Redirect convenience: allow /stream/tv/<id> (no .json) -> proper .json endpoint
app.get('/stream/tv/:id', (req: Request, res: Response, next: NextFunction) => {
    // Se giÃ  termina con .json non fare nulla
    if (req.originalUrl.endsWith('.json')) return next();
    const id = req.params.id;
    const q = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
    const target = `/stream/tv/${id}.json${q}`;
    res.redirect(302, target);
});

// Salva l'ultima request Express per fallback nel catalog handler (quando il router interno non passa req)
app.use((req: Request, _res: Response, next: NextFunction) => {
    (global as any).lastExpressRequest = req;
    next();
});

// âœ… CORRETTO: Annotazioni di tipo esplicite per Express
app.get('/', (_: Request, res: Response) => {
    const manifest: any = loadCustomConfig();
    try {
        // Resolve addon base exactly like extractor fallback chain
        const envBase = process.env.ADDON_BASE_URL || process.env.STREAMVIX_ADDON_BASE || '';
        const DEFAULT_ADDON_BASE = 'https://streamvix.hayd.uk';
        let resolved = '';
        if (manifest && typeof manifest === 'object' && manifest.addonBase) {
            resolved = String(manifest.addonBase);
        }
        if (!resolved && envBase && envBase.startsWith('http')) {
            resolved = envBase.replace(/\/$/, '');
        }
        if (!resolved) {
            resolved = DEFAULT_ADDON_BASE; // final fallback (mirrors extractor.ts logic)
        }
        manifest.__resolvedAddonBase = resolved; // inject for landing page display only (not part of config serialization)
    } catch (e) {
        console.warn('[Landing] addonBase resolution failed:', (e as any)?.message || e);
    }
    const landingHTML = landingTemplate(manifest);
    res.setHeader('Content-Type', 'text/html');
    res.send(landingHTML);
});

// Serve manifest dynamically so we can hide TV catalog when disableLiveTv is true
// Also supports config passed via path segment or query string (?config=...)
// CORS for manifest endpoints
app.options(['/manifest.json', '/:config/manifest.json', '/cfg/:config/manifest.json'], (_req: Request, res: Response) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    res.sendStatus(204);
});

app.get(['/manifest.json', '/:config/manifest.json', '/cfg/:config/manifest.json'], (req: Request, res: Response) => {
    try {
        const base = loadCustomConfig();
        // Parse optional config from URL segment OR query string (?config=...)
        const rawParamCfg = (req.params as any)?.config;
        const rawQueryCfg = typeof req.query.config === 'string' ? (req.query.config as string) : undefined;
        const cfgFromUrl = rawParamCfg ? parseConfigFromArgs(rawParamCfg) : (rawQueryCfg ? parseConfigFromArgs(rawQueryCfg) : {});
        // Build a manifest copy with defaults prefilled from cfgFromUrl or runtime cache
        const manifestWithDefaults: any = { ...base };
        const sourceCfg = (cfgFromUrl && Object.keys(cfgFromUrl).length) ? cfgFromUrl : (configCache as any);
        if (Array.isArray(manifestWithDefaults.config) && manifestWithDefaults.config.length) {
            manifestWithDefaults.config = manifestWithDefaults.config.map((c: any) => {
                const key = c?.key;
                if (!key) return c;
                const val = (sourceCfg as any)?.[key];
                if (typeof val !== 'undefined') {
                    if (c.type === 'checkbox') return { ...c, default: !!val };
                    else return { ...c, default: String(val) };
                }
                return c;
            });
        }
        const effectiveDisable = (cfgFromUrl as any)?.disableLiveTv ?? (configCache as any)?.disableLiveTv;
        const filtered: Manifest = { ...manifestWithDefaults } as Manifest;
        if (!Array.isArray((filtered as any).catalogs)) (filtered as any).catalogs = [];
        if (effectiveDisable) {
            const cats = Array.isArray(filtered.catalogs) ? filtered.catalogs.slice() : [];
            filtered.catalogs = cats.filter((c: any) => !(c && (c as any).id === 'streamvix_tv'));
        }
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
        res.json(filtered);
    } catch (e: any) {
        console.error('❌ Manifest route error:', e?.message || e);
        const fallback = loadCustomConfig();
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
        res.json(fallback);
    }
});

// Endpoint sintetico: genera mini-master con sola variante video massima e traccia AUDIO italiana
// Supporta sia /vixsynthetic che /vixsynthetic.m3u8 per compatibilità player
app.get(['/vixsynthetic', '/vixsynthetic.m3u8'], async (req: Request, res: Response) => {
    try {
        const src = typeof req.query.src === 'string' ? req.query.src : '';
        if (!src) return res.status(400).send('#EXTM3U\n# Missing src');
        const langPref = ((req.query.lang as string) || 'it').toLowerCase();
        const multiFlag = (() => {
            const m = String(req.query.multi || '').toLowerCase();
            if (['1', 'true', 'on', 'yes', 'all'].includes(m)) return true;
            if (String(req.query.languages || '').toLowerCase() === 'all') return true;
            return false;
        })();
        if (multiFlag) console.log('[vixsynthetic] multi-language mode attivo');
        const r = await fetch(src, { headers: { 'Accept': 'application/vnd.apple.mpegurl, application/x-mpegURL, */*' } as any });
        if (!r.ok) return res.status(502).send('#EXTM3U\n# Upstream error');
        const text = await r.text();
        // Se non Ã¨ master, restituisci com'Ã¨
        if (!/#EXT-X-STREAM-INF:/i.test(text)) {
            res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
            return res.send(text);
        }
        const lines = text.split(/\r?\n/);
        interface Variant { url: string; height: number; bandwidth: number; info: string; };
        const variants: Variant[] = [];
        const media: { line: string; attrs: Record<string, string>; }[] = [];
        const parseAttrs = (l: string): Record<string, string> => {
            const out: Record<string, string> = {}; l.replace(/([A-Z0-9-]+)=(("[^"]+")|([^,]+))/g, (_m, k, v) => { const val = String(v).replace(/^"|"$/g, ''); out[k] = val; return ''; }); return out;
        };
        for (let i = 0; i < lines.length; i++) {
            const l = lines[i];
            if (l.startsWith('#EXT-X-MEDIA:')) {
                media.push({ line: l, attrs: parseAttrs(l) });
            }
            if (l.startsWith('#EXT-X-STREAM-INF:')) {
                const info = l;
                const next = lines[i + 1] || '';
                if (!next || next.startsWith('#')) continue;
                const attrs = parseAttrs(info);
                let h = 0; let bw = 0;
                if (attrs['RESOLUTION']) {
                    const m = attrs['RESOLUTION'].match(/(\d+)x(\d+)/); if (m) h = parseInt(m[2], 10) || 0;
                }
                if (attrs['BANDWIDTH']) bw = parseInt(attrs['BANDWIDTH'], 10) || 0;
                // Resolve relative
                let vUrl = next.trim();
                try { vUrl = new URL(vUrl, src).toString(); } catch { }
                variants.push({ url: vUrl, height: h, bandwidth: bw, info });
            }
        }
        if (!variants.length) {
            res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
            return res.send(text);
        }
        variants.sort((a, b) => (b.height - a.height) || (b.bandwidth - a.bandwidth));
        const best = variants[0];
        const header: string[] = ['#EXTM3U'];
        const copyTags = ['#EXT-X-VERSION', '#EXT-X-INDEPENDENT-SEGMENTS'];
        for (const t of copyTags) { if (text.includes(t)) header.push(t); }

        if (multiFlag) {
            // In modalitÃ  multi includiamo tutte le righe #EXT-X-MEDIA (AUDIO e SUBTITLES) e manteniamo il GROUP-ID originale.
            const audioGroupsEncountered: Set<string> = new Set();
            const subtitleGroupsEncountered: Set<string> = new Set();
            for (const m of media) {
                const type = (m.attrs['TYPE'] || '').toUpperCase();
                if (type === 'AUDIO') {
                    header.push(m.line);
                    if (m.attrs['GROUP-ID']) audioGroupsEncountered.add(m.attrs['GROUP-ID']);
                } else if (type === 'SUBTITLES') {
                    header.push(m.line);
                    if (m.attrs['GROUP-ID']) subtitleGroupsEncountered.add(m.attrs['GROUP-ID']);
                }
            }
            // Forziamo la variante best ad usare il primo gruppo audio se presente
            let streamInf = best.info;
            if (audioGroupsEncountered.size) {
                const firstAudio = [...audioGroupsEncountered][0];
                if (/AUDIO="/.test(streamInf)) streamInf = streamInf.replace(/AUDIO="[^"]+"/, `AUDIO="${firstAudio}"`);
                else streamInf = streamInf.replace('#EXT-X-STREAM-INF:', `#EXT-X-STREAM-INF:AUDIO="${firstAudio}",`);
            }
            header.push(streamInf);
            header.push(best.url);
        } else {
            // ModalitÃ  singola (compatibile precedente): seleziona solo la traccia richiesta (langPref)
            let chosenGroup: string | null = null;
            let chosenMediaLine: string | null = null;
            for (const m of media) {
                const type = (m.attrs['TYPE'] || '').toUpperCase();
                if (type !== 'AUDIO') continue;
                const lang = (m.attrs['LANGUAGE'] || '').toLowerCase();
                const name = (m.attrs['NAME'] || '').toLowerCase();
                if (lang === langPref || name.includes(langPref)) {
                    chosenGroup = m.attrs['GROUP-ID'] || null;
                    chosenMediaLine = m.line;
                    break;
                }
            }
            if (!chosenGroup && media.length) {
                const firstAudio = media.find(m => (m.attrs['TYPE'] || '').toUpperCase() === 'AUDIO');
                if (firstAudio) { chosenGroup = firstAudio.attrs['GROUP-ID'] || null; chosenMediaLine = firstAudio.line; }
            }
            if (chosenMediaLine && chosenGroup) header.push(chosenMediaLine);
            let streamInf = best.info;
            if (chosenGroup) {
                if (/AUDIO="/.test(streamInf)) streamInf = streamInf.replace(/AUDIO="[^"]+"/, `AUDIO="${chosenGroup}"`);
                else streamInf = streamInf.replace('#EXT-X-STREAM-INF:', `#EXT-X-STREAM-INF:AUDIO="${chosenGroup}",`);
            }
            header.push(streamInf);
            header.push(best.url);
        }
        const mini = header.join('\n') + '\n';
        res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
        res.setHeader('Cache-Control', 'no-store');
        res.send(mini);
    } catch (e) {
        console.error('[vixsynthetic] error:', (e as any)?.message || e);
        res.status(500).send('#EXTM3U\n# internal error');
    }
});

// âœ… Middleware semplificato che usa sempre il router globale
app.use(async (req: Request, res: Response, next: NextFunction) => {
    // ...
    debugLog(`Incoming request: ${req.method} ${req.path}`);
    debugLog(`Full URL: ${req.url}`);
    debugLog(`Path segments:`, req.path.split('/'));
    try {
        const observedIp = await getClientIpFromReq(req);
        if (observedIp) vdbg('Observed client IP', { observedIp, reqIp: (req as any).ip, reqIps: (req as any).ips });
    } catch { }

    const configString = req.path.split('/')[1];
    debugLog(`Config string extracted: "${configString}" (length: ${configString ? configString.length : 0})`);

    // ...

    // Parse configuration from URL path segment once (before TV logic)
    if (configString && configString.length > 10 && !configString.startsWith('stream') && !configString.startsWith('meta') && !configString.startsWith('manifest')) {
        const parsedConfig = parseConfigFromArgs(configString);
        if (Object.keys(parsedConfig).length > 0) {
            debugLog('ðŸ”§ Found valid config in URL, updating global cache');
            Object.assign(configCache, parsedConfig);
            debugLog('ðŸ”§ Updated global config cache:', configCache);
        }
    }

    // Per le richieste di stream TV, assicurati che la configurazione proxy sia sempre presente
    if (req.url.includes('/stream/tv/') || req.url.includes('/stream/tv%3A')) {
        debugLog('ðŸ“º TV Stream request detected, ensuring MFP configuration');
        // Non applicare piÃ¹ nessun fallback hardcoded
        // if (!configCache.mfpProxyUrl || !configCache.mfpProxyPassword) { ... } // RIMOSSO
        debugLog('ðŸ“º Current proxy config for TV streams:', configCache);
    }

    // ...

    // PATCH: Inject full search query for AnimeWorld catalog search
    if (
        req.path === '/catalog/animeworld/anime/search.json' &&
        req.query && typeof req.query.query === 'string'
    ) {
        debugLog('ðŸ”Ž PATCH: Injecting full search query from req.query.query:', req.query.query);
        // Ensure req.query.extra is always an object
        let extraObj: any = {};
        if (req.query.extra) {
            if (typeof req.query.extra === 'string') {
                try {
                    extraObj = JSON.parse(req.query.extra);
                } catch (e) {
                    extraObj = {};
                }
            } else if (typeof req.query.extra === 'object') {
                extraObj = req.query.extra;
            }
        }
        extraObj.search = req.query.query;
        req.query.extra = extraObj;
    }

    // âœ… Inizializza il router globale se non Ã¨ ancora stato fatto
    const currentDisable = !!(configCache as any)?.disableLiveTv;
    const needRebuild = (!globalRouter) || (lastDisableLiveTvFlag !== currentDisable);
    if (needRebuild) {
        if (globalRouter) console.log('ðŸ” Rebuilding addon router due to config change (disableLiveTv=%s)', currentDisable);
        else console.log('ðŸ”§ Initializing global router...');
        globalBuilder = createBuilder(configCache);
        globalAddonInterface = globalBuilder.getInterface();
        globalRouter = getRouter(globalAddonInterface);
        lastDisableLiveTvFlag = currentDisable;
        console.log('âœ… Global router %s', needRebuild ? 'initialized/updated' : 'initialized');
    }

    // USA SEMPRE il router globale
    globalRouter(req, res, next);
});



function startServer(basePort: number, attempts = 0) {
    const PORT = basePort + attempts;
    const server = app.listen(PORT, () => {
        console.log(`Addon server running on http://127.0.0.1:${PORT}`);
    });
    server.on('error', (err: any) => {
        if (err.code === 'EADDRINUSE' && attempts < 10) {
            console.log(`âš ï¸ Porta ${PORT} occupata, provo con ${PORT + 1}...`);
            setTimeout(() => startServer(basePort, attempts + 1), 300);
        } else if (err.code === 'EADDRINUSE') {
            console.error(`âŒ Nessuna porta libera trovata dopo ${attempts + 1} tentativi partendo da ${basePort}`);
        } else {
            console.error('âŒ Errore server:', err);
        }
    });
}
const basePort = parseInt(process.env.PORT || '7860', 10);
startServer(basePort);






