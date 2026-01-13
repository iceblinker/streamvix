import "dotenv/config";
import { addonBuilder, getRouter, Manifest, Stream } from "stremio-addon-sdk";
import { getStreamContent, VixCloudStreamInfo, ExtractorConfig } from "./extractor";
import { mapLegacyProviderName, buildUnifiedStreamName, providerLabel } from './utils/unifiedNames';
import * as fs from 'fs';
import { landingTemplate } from './landingPage';
import * as path from 'path';
import express, { Request, Response, NextFunction } from 'express';

import { formatMediaFlowUrl } from './utils/mediaflow';

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

function debugLog(...args: any[]) { try { console.log('[DEBUG]', ...args); } catch { } }


// function getClientIpFromReq removed



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



// =====================================



// Funzione per determinare le categorie di un canale

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

    // Catalog logic removed


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
                                mfpUrl: config.mediaFlowProxyUrl,
                                mfpPsw: config.mediaFlowProxyPassword,
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
                console.log(`âœ… Total streams returned: ${allStreams.length}`);
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
        console.error('âŒ Manifest route error:', e?.message || e);
        const fallback = loadCustomConfig();
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
        res.json(fallback);
    }
});

// Endpoint sintetico: genera mini-master con sola variante video massima e traccia AUDIO italiana
// Supporta sia /vixsynthetic che /vixsynthetic.m3u8 per compatibilitÃ  player
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
app.use((req: Request, res: Response, next: NextFunction) => {
    // ...
    debugLog(`Incoming request: ${req.method} ${req.path}`);
    debugLog(`Full URL: ${req.url}`);
    debugLog(`Path segments:`, req.path.split('/'));


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





