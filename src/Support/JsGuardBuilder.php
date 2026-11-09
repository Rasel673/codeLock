<?php

namespace Rasel\CodeLock\Support;

/**
 * Generates an encrypted, self-decoding browser JavaScript guard for background
 * 5-minute license status synchronization and domain verification fallback.
 *
 * Security invariants:
 * - Zero secrets: never embeds license keys, activation tokens, or cryptographic signing keys.
 * - Cross-tab concurrency protection via localStorage lock.
 * - Strict no-self-DoS rule: renders restriction overlays ONLY on verified server denials.
 */
class JsGuardBuilder
{
    /**
     * Build the encrypted JS payload ready to be written to public/vendor/codelock/codelock-guard.js.
     */
    public function build(array $overrides = []): string
    {
        $source = $this->buildPlainSource($overrides);
        return $this->encryptPayload($source);
    }

    /**
     * Build the minified plain JavaScript logic containing only safe public metadata.
     */
    public function buildPlainSource(array $overrides = []): string
    {
        $configuredServerUrl = $this->safeConfig('codelock.server_url');
        if (empty($configuredServerUrl)) {
            $configuredServerUrl = $this->safeConfig('codelock.license_server_url', '');
        }
        $serverUrl = rtrim((string) ($overrides['server_url'] ?? $configuredServerUrl), '/');
        $productId = (string) ($overrides['product_id'] ?? $this->safeConfig('codelock.product_id', ''));
        $intervalMinutes = max(1, (int) ($overrides['interval_minutes'] ?? $this->safeConfig('codelock.js_guard.interval_minutes', 5)));
        $localSyncUrl = (string) ($overrides['local_sync_url'] ?? '/codelock/js-sync');
        $fallbackEnabled = (bool) ($overrides['fallback_server_check'] ?? $this->safeConfig('codelock.js_guard.fallback_server_check', true));
        $contactEmail = (string) ($overrides['contact_email'] ?? $this->safeConfig('codelock.contact_email', 'support@yourdomain.com'));

        $rawContactUrl = (string) ($overrides['contact_url'] ?? $this->safeConfig('codelock.contact_url', ''));
        $contactScheme = strtolower((string) parse_url($rawContactUrl, PHP_URL_SCHEME));
        $contactUrl = in_array($contactScheme, ['http', 'https'], true) ? $rawContactUrl : '';

        // Do not configure external fallback if pointing to unconfigured placeholder
        $fallbackUrl = '';
        if ($fallbackEnabled && !empty($serverUrl) && !str_contains($serverUrl, 'license.yourdomain.com')) {
            $fallbackUrl = $serverUrl . '/api/v1/public/domain-verify';
        }

        $config = [
            'lu' => $localSyncUrl,
            'fu' => $fallbackUrl,
            'pid' => $productId,
            'iv' => $intervalMinutes * 60 * 1000,
            'ce' => $contactEmail,
            'cu' => $contactUrl,
        ];

        $configJson = json_encode($config, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        return <<<JS
(function(){
"use strict";
var C={$configJson};
var K_TS="_cl_g_ts",K_LK="_cl_g_lk",K_ST="_cl_g_st",OV_ID="__cl_guard_overlay";
function lsGet(k){try{return window.localStorage?window.localStorage.getItem(k):null;}catch(e){return null;}}
function lsSet(k,v){try{if(window.localStorage)window.localStorage.setItem(k,String(v));}catch(e){}}
function safeUrl(u){try{if(!u)return null;var p=new URL(u,window.location.origin);return(p.protocol==="http:"||p.protocol==="https:")?p.href:null;}catch(e){return null;}}
function clearOv(){var e=document.getElementById(OV_ID);if(e&&e.parentNode)e.parentNode.removeChild(e);}
function showOv(info){
if(!info||info.valid!==false)return;
if(document.getElementById(OV_ID))return;
var wrap=document.createElement("div");
wrap.id=OV_ID;
wrap.style.cssText="position:fixed;inset:0;z-index:2147483647;background:rgba(2,6,23,0.96);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;padding:24px;font-family:system-ui,-apple-system,sans-serif;color:#f1f5f9;";
var card=document.createElement("div");
card.style.cssText="max-width:480px;width:100%;background:#0f172a;border:1px solid #334155;border-radius:16px;padding:32px;box-shadow:0 25px 50px -12px rgba(0,0,0,0.65);";
var badge=document.createElement("div");
badge.style.cssText="display:inline-block;padding:4px 10px;border-radius:9999px;background:rgba(168,85,247,0.15);border:1px solid rgba(168,85,247,0.35);color:#c084fc;font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:14px;";
badge.textContent=String(info.status||"LICENSE RESTRICTED");
var h=document.createElement("h2");
h.style.cssText="margin:0 0 10px 0;font-size:22px;font-weight:700;color:#ffffff;";
h.textContent="Software License Restricted";
var p=document.createElement("p");
p.style.cssText="margin:0 0 20px 0;font-size:14px;line-height:1.6;color:#94a3b8;";
p.textContent=String(info.message||"This application requires an active, authorized software license.");
var meta=document.createElement("div");
meta.style.cssText="padding:12px 14px;border-radius:10px;background:#020617;border:1px solid #1e293b;font-size:12px;color:#cbd5e1;margin-bottom:20px;";
meta.textContent="Domain: "+window.location.hostname+(info.code?" ("+info.code+")":"");
var act=document.createElement("div");
act.style.cssText="display:flex;flex-wrap:wrap;gap:10px;align-items:center;";
var supUrl=safeUrl(info.contact_url||C.cu);
if(supUrl){
var a=document.createElement("a");
a.href=supUrl;
a.target="_blank";
a.rel="noopener noreferrer";
a.style.cssText="display:inline-block;padding:10px 18px;background:#7e22ce;color:#ffffff;text-decoration:none;border-radius:8px;font-size:13px;font-weight:600;";
a.textContent="Contact Licensing Support";
act.appendChild(a);
}
var mail=info.contact_email||C.ce;
if(mail){
var m=document.createElement("span");
m.style.cssText="font-size:12px;color:#94a3b8;";
m.textContent="Support: "+String(mail);
act.appendChild(m);
}
card.appendChild(badge);card.appendChild(h);card.appendChild(p);card.appendChild(meta);card.appendChild(act);
wrap.appendChild(card);
if(document.body)document.body.appendChild(wrap);
}
function applyCached(){
try{
var raw=lsGet(K_ST);
if(!raw)return;
var st=JSON.parse(raw);
if(st&&st.verified===true&&st.valid===false){showOv(st);}
else if(st&&st.valid===true){clearOv();}
}catch(e){}
}
function fetchWithTimeout(url,opts){
var ctrl=(typeof AbortController!=="undefined")?new AbortController():null;
var t=ctrl?setTimeout(function(){ctrl.abort();},5000):null;
if(ctrl)opts.signal=ctrl.signal;
return fetch(url,opts).finally(function(){if(t)clearTimeout(t);});
}
function fallbackServerCheck(now){
if(!C.fu||!window.location.hostname)return;
fetchWithTimeout(C.fu,{
method:"POST",
mode:"cors",
headers:{"Content-Type":"application/json","Accept":"application/json"},
body:JSON.stringify({domain:window.location.hostname,product_id:C.pid,source:"js_guard_fallback"})
}).then(function(r){
if(!r||r.status===404||r.status>=500)return null;
return r.json().catch(function(){return null;});
}).then(function(d){
if(!d)return;
lsSet(K_TS,now);
if(d.verified===true&&(d.authorized===false||d.valid===false)){
var info={verified:true,valid:false,status:d.status||"UNAUTHORIZED",code:d.code||"E_DOMAIN_UNAUTHORIZED",message:d.message||"This installation is not authorized for "+window.location.hostname};
lsSet(K_ST,JSON.stringify(info));
showOv(info);
}else if(d.verified===true&&(d.authorized===true||d.valid===true)){
lsSet(K_ST,JSON.stringify({verified:true,valid:true,status:"ACTIVE"}));
clearOv();
}
}).catch(function(){});
}
function sync(){
var now=Date.now();
var last=parseInt(lsGet(K_TS)||"0",10);
var cachedInvalid=false;
try{var rawSt=lsGet(K_ST);if(rawSt){var pst=JSON.parse(rawSt);cachedInvalid=(pst&&pst.verified===true&&pst.valid===false);}}catch(e){}
var cooldown=cachedInvalid?Math.min(C.iv,30000):C.iv;
if(last>0&&last<=now&&(now-last)<cooldown){applyCached();return;}
var lk=parseInt(lsGet(K_LK)||"0",10);
if(lk>0&&lk<=now&&(now-lk)<15000){return;}
lsSet(K_LK,now);
fetchWithTimeout(C.lu,{
method:"POST",
headers:{"Content-Type":"application/json","Accept":"application/json"},
body:JSON.stringify({domain:window.location.hostname,ts:now})
}).then(function(r){
if(!r)return;
if(r.status===404||r.status===405){fallbackServerCheck(now);return;}
if(r.status>=500)return;
r.json().then(function(d){
if(!d)return;
lsSet(K_TS,now);
if(d.verified===true){
lsSet(K_ST,JSON.stringify(d));
if(d.valid===false){showOv(d);}else{clearOv();}
}
}).catch(function(){});
}).catch(function(){});
}
function init(){
applyCached();
setTimeout(sync,1500);
setInterval(sync,C.iv);
}
if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",init);}else{init();}
})();
JS;
    }

    /**
     * Encrypt plain JS using pure-PHP RC4 stream cipher + Base64 encoding and wrap
     * in a minimal self-decoding anonymous browser bootstrapper.
     */
    public function encryptPayload(string $plainJs, ?string $key = null): string
    {
        $rawKey = $key ?? bin2hex(random_bytes(16));
        $cipherBytes = $this->rc4($rawKey, $plainJs);
        $cipherB64 = base64_encode($cipherBytes);
        $keyLiteral = json_encode($rawKey, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $cipherLiteral = json_encode($cipherB64, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        return "/* CodeLock Runtime Protection Guard */\n"
            . "(function(k,c){try{"
            . "var b=atob(c),n=b.length,s=[],i,j=0,x,r=new Uint8Array(n);"
            . "for(i=0;i<256;i++)s[i]=i;"
            . "for(i=0;i<256;i++){j=(j+s[i]+k.charCodeAt(i%k.length))%256;x=s[i];s[i]=s[j];s[j]=x;}"
            . "i=0;j=0;for(var y=0;y<n;y++){i=(i+1)%256;j=(j+s[i])%256;x=s[i];s[i]=s[j];s[j]=x;r[y]=b.charCodeAt(y)^s[(s[i]+s[j])%256];}"
            . "var d=(typeof TextDecoder!=='undefined')?new TextDecoder('utf-8').decode(r):decodeURIComponent(escape(String.fromCharCode.apply(null,r)));"
            . "(new Function(d))();"
            . "}catch(e){}})({$keyLiteral},{$cipherLiteral});\n";
    }

    /**
     * Pure-PHP RC4 stream cipher implementation (matches browser bootstrapper KSA/PRGA).
     */
    public function rc4(string $key, string $data): string
    {
        $s = range(0, 255);
        $j = 0;
        $keyLen = strlen($key);
        for ($i = 0; $i < 256; $i++) {
            $j = ($j + $s[$i] + ord($key[$i % $keyLen])) % 256;
            $tmp = $s[$i];
            $s[$i] = $s[$j];
            $s[$j] = $tmp;
        }

        $i = 0;
        $j = 0;
        $out = '';
        $dataLen = strlen($data);
        for ($y = 0; $y < $dataLen; $y++) {
            $i = ($i + 1) % 256;
            $j = ($j + $s[$i]) % 256;
            $tmp = $s[$i];
            $s[$i] = $s[$j];
            $s[$j] = $tmp;
            $k = $s[($s[$i] + $s[$j]) % 256];
            $out .= chr(ord($data[$y]) ^ $k);
        }

        return $out;
    }

    /**
     * Publish the encrypted JS guard directly into the target public path atomically.
     */
    public function writeToPublicPath(?string $targetPath = null, array $overrides = []): string
    {
        $relPath = ltrim((string) $this->safeConfig('codelock.js_guard.asset_path', 'vendor/codelock/codelock-guard.js'), '/\\');
        $path = $targetPath ?? (function_exists('public_path') ? public_path($relPath) : getcwd() . '/public/' . $relPath);

        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            throw new \RuntimeException("Unable to create directory [{$dir}] for CodeLock JS guard.");
        }

        $content = $this->build($overrides);
        $tmpPath = $path . '.tmp.' . bin2hex(random_bytes(4));

        if (@file_put_contents($tmpPath, $content, LOCK_EX) === false) {
            throw new \RuntimeException("Unable to write CodeLock JS guard asset to [{$path}].");
        }

        if (!@rename($tmpPath, $path)) {
            @unlink($tmpPath);
            if (@file_put_contents($path, $content, LOCK_EX) === false) {
                throw new \RuntimeException("Unable to publish CodeLock JS guard asset to [{$path}].");
            }
        }

        return $path;
    }

    /**
     * Safely resolve configuration even if invoked outside a full Laravel container.
     */
    protected function safeConfig(string $key, mixed $default = null): mixed
    {
        try {
            if (function_exists('app') && app()->bound('config')) {
                return config($key, $default);
            }
        } catch (\Throwable $e) {
            // Fall back to default
        }

        return $default;
    }
}
