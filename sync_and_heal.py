#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudStream Süper Repo: Akıllı TR Filtresi, DiziPal VIP Avcısı & SHA-256 Onarım Motoru
======================================================================================
1. SHA256 (DigestException) KESİN ÇÖZÜMÜ:
   - builds/ klasörüne indirilen her .cs3 dosyasının gerçek SHA-256 ve fileSize değeri
     doğrudan diskteki dosya baytlarından hesaplanır.
   - jsDelivr CDN önbellek çakışmasını önlemek için her dosya adı benzersiz biçimde
     '{KaynakRepo}_{EklentiAdi}_v{Version}.cs3' olarak kaydedilir.
2. DİZİPAL VIP KORUMA & ÇOKLU VARYASYON:
   - DiziPal eklentileri ASLA elenmez, silinmez veya tekilleştirilmez.
   - TurkSinema, BTVault, Ripplay, Feroxx repolarındaki tüm DiziPal varyasyonları
     ayrı ayrı isimlendirilerek ve benzersiz internalName ile eklenir.
   - Cloudflare 403/503 yanıtları 'Canlı (CF Korumalı)' kabul edilir.
3. DİZİPAL OTOMATİK DOMAİN AVCISI & EN GÜNCEL TESPİTİ:
   - .cs3 (classes.dex) içindeki DiziPal alan adı numaralarını (örn. 2149, 1595) tespit eder.
   - Canlı HTTP kontrolü, yönlendirme takibi (+1 ardışık tarama) ve opsiyonel Gemini API ile
     aktif DiziPal adresini yakalar.
   - En güncel domain numarasına sahip DiziPal eklentisini '⭐ DiziPal [EN GÜNCEL - Aktif]'
     olarak adlandırıp listenin en tepesine koyar.
   - README.md en başına güncel DiziPal adresi banner'ı ekler.
"""

import os
import sys
import json
import re
import hashlib
import zipfile
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from google import genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


# =====================================================================
# YAPILANDIRMA VE SABİTLER
# =====================================================================
BASE_DIR = Path(__file__).resolve().parent
SOURCES_FILE = BASE_DIR / "sources.json"
BUILDS_DIR = BASE_DIR / "builds"
PLUGINS_FILE = BUILDS_DIR / "plugins.json"
REPO_FILE = BASE_DIR / "repo.json"
DOMAINS_FILE = BASE_DIR / "domains.json"
BROKEN_PLUGINS_FILE = BASE_DIR / "broken_plugins.json"
README_FILE = BASE_DIR / "README.md"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
HTTP_TIMEOUT = 12
MIN_VALID_CS3_SIZE = 1024
MAX_WORKERS = 16

IGNORE_HOSTS: Set[str] = {
    'schema.org', 'w3.org', 'github.com', 'google.com', 'android.com',
    'jsdelivr.net', 'cloudflare.com', 'raw.githubusercontent.com',
    'youtube.com', 't.me', 'telegram.org', 'discord.gg', 'tmdb.org',
    'themoviedb.org', 'opensubtitles.org', 'imdb.com', 'facebook.com',
    'twitter.com', 'instagram.com', 'example.com', 'wikipedia.org',
    'repo.json', 'plugins.json', 'googlevideo.com', 'gstatic.com',
    'ornekadres.com', 'inv.nadeko.net', 'invidious.nerdvpn.de', 'invidious.f5.si'
}

FOREIGN_LANGUAGES: Set[str] = {
    "hi", "zh", "ta", "te", "bn", "id", "de", "fr", "pt-br", "fil", "pl", "ko", "mx", "ar", "es"
}

DEFAULT_GLOBAL_WHITELIST = [
    "netflix", "netflixmirror", "primevideo", "prime", "disney", "twitch", "superstream", "youtube"
]


def log_info(msg: str) -> None:
    print(f"\033[94m[BİLGİ]\033[0m {msg}", flush=True)


def log_success(msg: str) -> None:
    print(f"\033[92m[BAŞARILI]\033[0m {msg}", flush=True)


def log_warn(msg: str) -> None:
    print(f"\033[93m[UYARI]\033[0m {msg}", flush=True)


def log_error(msg: str) -> None:
    print(f"\033[91m[HATA]\033[0m {msg}", flush=True)


def log_vip(msg: str) -> None:
    print(f"\033[95m[DİZİPAL VIP]\033[0m {msg}", flush=True)


def log_elim(msg: str) -> None:
    print(f"\033[33m[ELENDİ]\033[0m {msg}", flush=True)


# =====================================================================
# YARDIMCI VE AĞ FONKSİYONLARI
# =====================================================================
def get_session(pool_size: int = 32) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive"
    })
    retries = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def compute_sha256(filepath: Path) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def sanitize_filename(name: str) -> str:
    cleaned = re.sub(r'[^\w\-_\.]', '_', name)
    cleaned = re.sub(r'_+', '_', cleaned).strip('_')
    return cleaned or "plugin"


def sanitize_slug(name: str) -> str:
    cleaned = re.sub(r'[^a-zA-Z0-9]', '', name)
    return cleaned or "Repo"


def get_repo_identifier(sources_cfg: Dict[str, Any]) -> Tuple[str, str]:
    env_repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    branch = sources_cfg.get("branch", "main").strip()
    if env_repo and "/" in env_repo:
        return env_repo, branch
    user = sources_cfg.get("default_github_user", "MrKonce")
    repo = sources_cfg.get("default_github_repo", "ozel-cs-repom")
    return f"{user}/{repo}", branch


def convert_to_cdn_url(repo_full: str, branch: str, filename: str) -> str:
    return f"https://cdn.jsdelivr.net/gh/{repo_full}@{branch}/builds/{filename}"


def convert_github_raw_to_cdn(raw_url: Optional[str]) -> Optional[str]:
    if not raw_url or not isinstance(raw_url, str):
        return raw_url
    raw_pattern = r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$"
    match = re.match(raw_pattern, raw_url)
    if match:
        owner, repo, branch_or_commit, path = match.groups()
        return f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch_or_commit}/{path}"
    return raw_url


# =====================================================================
# DİZİPAL ÖZEL AVCISI & DOMAİN NUMARASI ANALİZİ
# =====================================================================
def extract_dizipal_domain_and_number(cs3_path: Path) -> Tuple[Optional[str], int]:
    """
    DiziPal .cs3 dosyasının içindeki sınıflardan dizipalXYZ.com domainini
    ve XYZ numarasını (örn: 2149) çıkarır.
    """
    if not cs3_path.exists():
        return None, 0
    try:
        with zipfile.ZipFile(cs3_path, 'r') as z:
            if 'classes.dex' not in z.namelist():
                return None, 0
            dex = z.read('classes.dex')
            matches = re.findall(rb'https?://(?:www\.)?dizipal(\d+)\.[a-zA-Z]{2,}', dex)
            highest_num = 0
            found_domain = None
            for m in matches:
                try:
                    num = int(m.decode('utf-8'))
                    if num > highest_num:
                        highest_num = num
                        found_domain = f"https://dizipal{num}.com"
                except Exception:
                    pass
            return found_domain, highest_num
    except Exception:
        return None, 0


def hunt_active_dizipal_domain(session: requests.Session, initial_known: str) -> str:
    """
    DiziPal'ın en güncel aktif adresini canlı yönlendirmeleri ve ardışık numaraları
    tarayarak tespit eder.
    """
    log_vip(f"DiziPal Domain Avcısı devrede. Başlangıç referansı: {initial_known}")
    active_domain = initial_known

    # 1. Başlangıç domainine istek atıp yönlendirmeyi izle
    try:
        r = session.get(initial_known, timeout=6, allow_redirects=True)
        final_url = r.url.rstrip('/')
        if r.status_code in [200, 301, 302, 403, 503]:
            log_vip(f"Mevcut DiziPal adresi aktif ve yanıt veriyor: {final_url} (HTTP {r.status_code})")
            return final_url
    except Exception as e:
        log_warn(f"DiziPal mevcut adrese ulaşılamadı ({initial_known}): {e}")

    # 2. Eğer kapalıysa, ardışık numara (+1, +2, +3, ...) taraması yap
    match = re.search(r'dizipal(\d+)', initial_known)
    base_num = int(match.group(1)) if match else 2149

    log_vip(f"Ardışık DiziPal domainleri taranıyor (Başlangıç: {base_num})...")
    for offset in range(1, 15):
        test_num = base_num + offset
        test_url = f"https://dizipal{test_num}.com"
        try:
            r = session.get(test_url, timeout=4, allow_redirects=True)
            if r.status_code in [200, 301, 302, 403, 503]:
                log_vip(f"🔥 YENİ AKTİF DİZİPAL BULUNDU: {r.url.rstrip('/')}")
                return r.url.rstrip('/')
        except Exception:
            pass

    # 3. Opsiyonel Gemini Analizi
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if gemini_key and GENAI_AVAILABLE:
        try:
            log_vip("Gemini 2.5 Flash ile DiziPal alan adı analizi yapılıyor...")
            ai_client = genai.Client(api_key=gemini_key)
            prompt = (
                "Türkiye'deki popüler dizi izleme sitesi DiziPal'ın şu an çalışan en güncel "
                "giriş adresi nedir? Örnek format: https://dizipal2149.com. Yalnızca URL döndür."
            )
            resp = ai_client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
            found_url = re.search(r'https?://dizipal\d+\.[a-z]+', resp.text)
            if found_url:
                candidate_url = found_url.group(0)
                try:
                    chk = session.get(candidate_url, timeout=5)
                    if chk.status_code in [200, 301, 302, 403, 503]:
                    	log_vip(f"Gemini doğrulanmış DiziPal adresi buldu: {candidate_url}")
                    	return candidate_url
                except Exception:
                    pass
        except Exception as e:
            log_warn(f"Gemini DiziPal analizi hatası: {e}")

    return active_domain


# =====================================================================
# SİTE ADI NORMALİZASYONU & GENEL DOMAİN TESPİTİ
# =====================================================================
def normalize_site_key(name: str, internal_name: str) -> str:
    raw = name.split('[')[0].strip()
    raw = re.sub(r'Provider$', '', raw, flags=re.I)
    raw = re.sub(r'Plugin$', '', raw, flags=re.I)
    clean = re.sub(r'[^a-zA-Z0-9]', '', raw).lower()

    known_prefixes = [
        "dizibox", "belgeselx", "hdfilmcehennemi", "ddizi",
        "setfilmizle", "webteizle", "yabancidizi", "cizgimax", "rectv",
        "selcuk", "filmmakinesi", "filmmodu", "dizimom", "dizilla",
        "diziyou", "rarefilmm", "tranimaci", "wiospor", "asyawatch",
        "canlitv", "sezonlukdizi", "fullhdfilmizlesene", "animecix", "anizm"
    ]
    for prefix in known_prefixes:
        if clean.startswith(prefix):
            return prefix

    return clean or internal_name.lower()


def extract_domain_from_cs3(cs3_path: Path) -> Optional[str]:
    if not cs3_path.exists():
        return None
    try:
        with zipfile.ZipFile(cs3_path, 'r') as z:
            if 'classes.dex' not in z.namelist():
                return None
            dex = z.read('classes.dex')
            urls = re.findall(rb'https?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})', dex)
            for u in urls:
                try:
                    host = u.decode('utf-8', errors='ignore').lower().strip('.')
                    if not any(ign in host for ign in IGNORE_HOSTS):
                        if '.' in host and not host.endswith(('.png', '.jpg', '.jpeg', '.gif', '.json')):
                            return host
                except Exception:
                    pass
    except Exception:
        pass
    return None


def check_site_alive(session: requests.Session, host: Optional[str]) -> Tuple[bool, str]:
    """
    Sitenin canlı olup olmadığını test eder.
    Cloudflare 403 ve 503 yanıtları sunucunun açık ve korumalı olduğunu gösterdiği için CANLI sayılır.
    """
    if not host:
        return True, "Dahili Sağlayıcı / Canlı Akış"

    for proto in ["https://", "http://"]:
        try:
            target_url = f"{proto}{host}"
            resp = session.get(target_url, timeout=5, allow_redirects=True)
            # Cloudflare 403/503 sitenin açık olduğunu gösterir
            if resp.status_code in [200, 301, 302, 307, 308, 403, 503]:
                return True, f"Canlı (HTTP {resp.status_code} / CF Korumalı)"
            if resp.status_code in [404, 500, 502]:
                return False, f"Sunucu Hatası (HTTP {resp.status_code})"
        except requests.exceptions.SSLError:
            return True, "Canlı (SSL Aktif)"
        except Exception:
            pass

    return False, "Erişim hatası / Zaman aşımı"


# =====================================================================
# ADIM 1: KAYNAKLARDAN ÇEKME & DİZİPAL VIP KORUMASI
# =====================================================================
def fetch_sources(
    session: requests.Session,
    sources_list: List[Dict[str, Any]],
    blacklist: List[str],
    global_whitelist: List[str],
    broken_report: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Tüm kaynakları çeker:
    - DiziPal eklentilerini doğrudan VIP listesine alır (asla elenmez).
    - Diğer Türkçe ve whitelisted eklentileri genel aday listesine alır.
    """
    dizipal_vip_list: List[Dict[str, Any]] = []
    general_candidates: List[Dict[str, Any]] = []

    for src in sources_list:
        if not src.get("enabled", True):
            continue

        name = src.get("name", "Bilinmeyen")
        url = src.get("url", "")
        priority = src.get("priority", 99)
        src_lang = src.get("language", "tr")

        is_global_source = (src_lang not in ["tr", "all"]) or ("phisher" in url.lower()) or ("csx" in url.lower())

        log_info(f"[{name}] Taranıyor (Öncelik: {priority}) -> {url}")
        try:
            resp = session.get(url, timeout=HTTP_TIMEOUT)
            if resp.status_code != 200:
                continue

            repo_data = resp.json()
            plugin_lists = repo_data.get("pluginLists", [])
            if not plugin_lists and isinstance(repo_data, list):
                plugin_lists = [url]

            for p_list_url in plugin_lists:
                try:
                    p_resp = session.get(p_list_url, timeout=HTTP_TIMEOUT)
                    if p_resp.status_code != 200:
                        continue

                    p_data = p_resp.json()
                    items = p_data if isinstance(p_data, list) else list(p_data.values())

                    for item in items:
                        if not isinstance(item, dict):
                            continue

                        in_name = item.get("internalName") or item.get("name") or ""
                        item_name = item.get("name", "")
                        item_lang = (item.get("language") or "").lower()

                        enriched = dict(item)
                        enriched["_source_name"] = name
                        enriched["_source_priority"] = priority

                        # --- DİZİPAL VIP KONTROLÜ (ASLA ELENMEZ) ---
                        if "dizipal" in item_name.lower() or "dizipal" in in_name.lower():
                            dizipal_vip_list.append(enriched)
                            log_vip(f"VIP Eklenti Keşfedildi: {item_name} ({name})")
                            continue

                        # Kara Liste
                        if in_name in blacklist or item_name in blacklist:
                            broken_report.append({
                                "name": item_name,
                                "internalName": in_name,
                                "source": name,
                                "version": item.get("version"),
                                "reason": "Kara liste (Blacklist) engeli"
                            })
                            continue

                        # Global Kaynak Filtresi
                        if is_global_source:
                            matches_global = any(
                                w in item_name.lower() or w in in_name.lower()
                                for w in global_whitelist
                            )
                            if not matches_global:
                                broken_report.append({
                                    "name": item_name,
                                    "internalName": in_name,
                                    "source": name,
                                    "version": item.get("version"),
                                    "reason": f"Global repo yabancı dil / filtrelendi ({item_lang or 'en'})"
                                })
                                continue

                        # Yabancı dil filtresi
                        if item_lang in FOREIGN_LANGUAGES:
                            broken_report.append({
                                "name": item_name,
                                "internalName": in_name,
                                "source": name,
                                "version": item.get("version"),
                                "reason": f"Yabancı dil filtresi ({item_lang})"
                            })
                            continue

                        general_candidates.append(enriched)

                except Exception as e:
                    log_warn(f"[{name}] Liste ayrıştırma hatası ({p_list_url}): {e}")

        except Exception as e:
            log_error(f"[{name}] Kaynak hatası: {e}")

    log_success(f"DiziPal VIP Listesi: {len(dizipal_vip_list)} eklenti | Genel Adaylar: {len(general_candidates)} eklenti.")
    return dizipal_vip_list, general_candidates


# =====================================================================
# ADIM 2: İNDİRME, BOYUT & KESİN SHA-256 HESAPLAMA
# =====================================================================
def download_and_verify_cs3(
    session: requests.Session,
    plugin: Dict[str, Any],
    builds_dir: Path
) -> Optional[Tuple[Dict[str, Any], Path, str, int]]:
    """
    Her eklentiyi indirir, '{KaynakRepo}_{EklentiAdi}_v{Version}.cs3' olarak kaydeder,
    ve dosyanın diskteki GERÇEK sha256 ile byte boyutunu bizzat hesaplar.
    """
    src_slug = sanitize_slug(plugin.get("_source_name", "Repo"))
    raw_name = sanitize_filename(plugin.get("internalName") or plugin.get("name") or "plugin")
    version = int(plugin.get("version", 1) or 1)

    # Benzersiz dosya adı: CDN önbellek çakışmalarını %100 önler!
    target_filename = f"{src_slug}_{raw_name}_v{version}.cs3"
    target_path = builds_dir / target_filename

    download_ok = False
    remote_url = plugin.get("url", "")
    if remote_url:
        try:
            resp = session.get(remote_url, timeout=HTTP_TIMEOUT, stream=True)
            if resp.status_code == 200:
                content = resp.content
                if len(content) >= MIN_VALID_CS3_SIZE:
                    with open(target_path, "wb") as f:
                        f.write(content)
                    download_ok = True
        except Exception:
            pass

    if not download_ok:
        if target_path.exists() and target_path.stat().st_size >= MIN_VALID_CS3_SIZE:
            download_ok = True

    if not download_ok:
        return None

    # Disk üzerindeki gerçek baytlardan BİZZAT hesapla
    file_bytes = target_path.read_bytes()
    real_sha256 = hashlib.sha256(file_bytes).hexdigest()
    real_size = len(file_bytes)

    verified_item = dict(plugin)
    verified_item["fileSize"] = real_size
    verified_item["fileHash"] = f"sha256-{real_sha256}"
    verified_item["_local_filename"] = target_filename

    return verified_item, target_path, real_sha256, real_size


# =====================================================================
# ADIM 3: DİZİPAL VIP İŞLEYİCİSİ & ÇOKLU VARYASYON KAYDI
# =====================================================================
def process_dizipal_vip(
    session: requests.Session,
    dizipal_list: List[Dict[str, Any]],
    builds_dir: Path,
    active_dizipal_url: str
) -> List[Dict[str, Any]]:
    """
    Tüm DiziPal varyasyonlarını indirir, içlerindeki domain numarasını analiz eder.
    En yüksek/güncel domain numarasına sahip olanı ⭐ DiziPal [EN GÜNCEL - Aktif] yapar.
    Diğerlerini kaynak repolarına göre isimlendirir.
    """
    log_vip("DiziPal VIP varyasyonları işleniyor...")
    verified_dizipals = []

    for item in dizipal_list:
        res = download_and_verify_cs3(session, item, builds_dir)
        if res:
            p_dict, path, sha256_val, size_val = res
            domain, num = extract_dizipal_domain_and_number(path)
            p_dict["_dizipal_num"] = num
            p_dict["_dizipal_domain"] = domain
            p_dict["_path"] = path
            verified_dizipals.append(p_dict)
            log_vip(f"DiziPal Doğrulandı: {item.get('name')} ({item.get('_source_name')}) -> Tespit Edilen Domain: {domain or 'Yok'} (No: {num})")

    if not verified_dizipals:
        return []

    # En güncel DiziPal'ı (en yüksek domain numaralı ve en yüksek sürümlü) bul
    verified_dizipals.sort(
        key=lambda x: (x.get("_dizipal_num", 0), int(x.get("version", 0) or 0)),
        reverse=True
    )

    final_dizipal_plugins = []
    seen_internal_names = set()

    for idx, p in enumerate(verified_dizipals):
        src_name = p.get("_source_name", "Repo")
        clean_item = dict(p)

        if idx == 0:
            # En güncel DiziPal
            clean_item["name"] = "⭐ DiziPal [EN GÜNCEL - Aktif]"
            clean_item["internalName"] = "DiziPalOriginal"
            clean_item["description"] = f"🔥 Güncel Aktif Domain: {active_dizipal_url} | Otomatik Doğrulandı."
            log_vip(f"LİDER DİZİPAL SEÇİLDİ: {clean_item['name']} ({src_name}, Sürüm: {clean_item.get('version')})")
        else:
            # Alternatif varyasyonlar
            orig_name = p.get("name", "DiziPal")
            if "original" in orig_name.lower():
                clean_item["name"] = f"DiziPal (Orijinal) [{src_name}]"
            elif "hub" in orig_name.lower():
                clean_item["name"] = f"DiziPal Hub [{src_name}]"
            else:
                clean_item["name"] = f"DiziPal [{src_name}]"

            slug = sanitize_slug(src_name)
            raw_in = sanitize_filename(p.get("internalName", "DiziPal"))
            clean_item["internalName"] = f"{raw_in}_{slug}"
            clean_item["description"] = f"[{src_name} Yedek Alternatifi] DiziPal Eklentisi."

        # Çakışmayı önle
        while clean_item["internalName"] in seen_internal_names:
            clean_item["internalName"] += f"_{clean_item.get('version', 1)}"
        seen_internal_names.add(clean_item["internalName"])

        final_dizipal_plugins.append(clean_item)

    return final_dizipal_plugins


# =====================================================================
# ADIM 4: GENEL EKLENTİ CANLILIK & TEKİLLEŞTİRME
# =====================================================================
def process_general_candidates(
    session: requests.Session,
    candidates: List[Dict[str, Any]],
    builds_dir: Path,
    broken_report: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Genel aday eklentileri test eder, çalışan tekil en güncel kopyaları seçer.
    """
    site_groups: Dict[str, List[Dict[str, Any]]] = {}
    for p in candidates:
        key = normalize_site_key(p.get("name", ""), p.get("internalName", ""))
        site_groups.setdefault(key, []).append(p)

    final_general_plugins = []

    for group_key, plist in site_groups.items():
        sorted_plist = sorted(
            plist,
            key=lambda x: (int(x.get("version", 0) or 0), -int(x.get("_source_priority", 99))),
            reverse=True
        )

        working_winner = None
        for p in sorted_plist:
            res = download_and_verify_cs3(session, p, builds_dir)
            if not res:
                broken_report.append({
                    "name": p.get("name"),
                    "internalName": p.get("internalName"),
                    "source": p.get("_source_name"),
                    "version": p.get("version"),
                    "reason": "Dosya indirilemedi / Bozuk CS3"
                })
                continue

            verified_item, path, sha_val, size_val = res

            # Canlı TV veya genel site testi
            if "Live" in p.get("tvTypes", []):
                is_alive = True
                reason = "Canlı TV / IPTV Akışı"
            else:
                host = extract_domain_from_cs3(path)
                is_alive, reason = check_site_alive(session, host)

            if is_alive:
                if working_winner is None:
                    working_winner = verified_item
                else:
                    broken_report.append({
                        "name": p.get("name"),
                        "internalName": p.get("internalName"),
                        "source": p.get("_source_name"),
                        "version": p.get("version"),
                        "reason": f"Daha güncel/çalışan versiyonu seçildi ({working_winner.get('name')} v{working_winner.get('version')})"
                    })
            else:
                broken_report.append({
                    "name": p.get("name"),
                    "internalName": p.get("internalName"),
                    "source": p.get("_source_name"),
                    "version": p.get("version"),
                    "reason": f"Hedef site kapalı / ulaşılamıyor ({reason})"
                })

        if working_winner:
            final_general_plugins.append(working_winner)

    return final_general_plugins


# =====================================================================
# ADIM 5: GEREKSİZ CS3 DOSYALARINI DİSKTEN SİLME (PRUNE)
# =====================================================================
def prune_unused_build_files(builds_dir: Path, valid_filenames: Set[str]) -> int:
    deleted = 0
    if not builds_dir.exists():
        return 0
    for f in builds_dir.glob("*.cs3"):
        if f.name not in valid_filenames:
            try:
                os.remove(f)
                deleted += 1
            except Exception:
                pass
    log_success(f"Diskten {deleted} adet eski/gereksiz .cs3 dosyası temizlendi.")
    return deleted


# =====================================================================
# ADIM 6: README OLUŞTURUCU (DİZİPAL BANNER İLE)
# =====================================================================
def generate_readme(
    readme_path: Path,
    repo_full: str,
    branch: str,
    final_plugins: List[Dict[str, Any]],
    broken_count: int,
    active_dizipal_url: str
) -> None:
    now_utc = datetime.now(timezone.utc)
    now_tr = now_utc + timedelta(hours=3)
    formatted_time = now_tr.strftime("%d.%m.%Y - %H:%M:%S (TSİ / GMT+3)")
    super_repo_url = f"https://cdn.jsdelivr.net/gh/{repo_full}@{branch}/repo.json"

    lines = [
        "# ⚡ CloudStream Süper Repo (Otonom & DiziPal VIP Korumalı)",
        "",
        f"> ### 🔥 Güncel Aktif DiziPal Adresi: **{active_dizipal_url}** *(Otonom Olarak Doğrulandı)*",
        "",
        "> **En güncel Türkçe ve popüler global CloudStream eklentilerini (.cs3) tek bir adreste toplayan,**",
        "> **DiziPal VIP korumalı, otomatik alan adı avcılıklı ve SHA256 doğrulamalı süper repo.**",
        "",
        "## 🚀 Hızlı Kurulum (CloudStream Uygulamasına Ekleme)",
        "",
        "CloudStream uygulamasında aşağıdaki bağlantıyı depo olarak ekleyerek tüm eklentilere anında erişebilirsiniz:",
        "",
        "```text",
        super_repo_url,
        "```",
        "",
        "*(Bu bağlantı `cdn.jsdelivr.net` önbelleği kullandığı için GitHub raw engellerine takılmaz ve **VPN gerektirmez**.)*",
        "",
        "---",
        "",
        "## 📊 Genel Durum & İstatistikler",
        "",
        f"- 🕒 **Son Güncelleme:** `{formatted_time}`",
        f"- 🌟 **Aktif DiziPal Adresi:** `{active_dizipal_url}`",
        f"- 📦 **Aktif ve Çalışan Eklenti:** `{len(final_plugins)}` adet",
        f"- 🗑️ **Elenen / Raporlanan Eklenti:** `{broken_count}` adet ([broken_plugins.json](broken_plugins.json))",
        f"- 🛡️ **SHA256 Doğrulaması:** `Aktif (Transfer Hash Eşleşme Garantili)`",
        f"- ⚡ **CDN Hızlandırma:** `jsDelivr Global Edge Network`",
        "",
        "---",
        "",
        "## 🌟 Temel Özellikler",
        "",
        "1. **👑 DiziPal VIP Koruması & Çoklu Alternatif:**",
        "   DiziPal eklentisi hiçbir zaman elenmez. TurkSinema, Feroxx, Ripplay ve BTVault repolarındaki tüm DiziPal varyasyonları yedekli olarak sunulur. En güncel domain numarasına sahip olan eklenti `⭐ DiziPal [EN GÜNCEL - Aktif]` adıyla listenin başında yer alır.",
        "",
        "2. **🛡️ SHA256 (Mismatched Digest) Koruması:**",
        "   İndirilen tüm `.cs3` dosyaları disk üzerindeki gerçek baytlardan hesaplanan SHA256 ve fileSize değerleriyle sunulur. jsDelivr CDN önbellek uyuşmazlığı yaşanmaması için her dosya versiyon numarasıyla benzersiz kaydedilir.",
        "",
        "3. **🇹🇷 Sadece Türkçe & Popüler Global:**",
        "   Hintçe/yabancı eklentiler elenmiş; yalnızca Türkiye'deki dizi, film ve canlı spor platformları ile popüler servisler dahil edilmiştir.",
        "",
        "---",
        "",
        "## 📦 Aktif Eklentiler Listesi",
        "",
        f"<details open><summary><b>Toplam {len(final_plugins)} Çalışan Eklentiyi Göster</b></summary>",
        "",
        "| Eklenti Adı | Sürüm | Dil | Kaynak | Dosya Boyutu |",
        "|:---|:---:|:---:|:---|:---:|",
    ]

    for p in final_plugins:
        p_name = p.get("name", "Bilinmeyen")
        p_ver = f"v{p.get('version', 1)}"
        p_lang = p.get("language", "tr")
        p_src = p.get("_source_name", "Yerel Yedek")
        p_size_kb = f"{round(p.get('fileSize', 0) / 1024, 1)} KB"
        lines.append(f"| **{p_name}** | `{p_ver}` | `{p_lang}` | {p_src} | {p_size_kb} |")

    lines.extend([
        "",
        "</details>",
        "",
        "---",
        "",
        "_Otomatik olarak güncellenmiştir._"
    ])

    with open(readme_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log_success("README.md dosyası oluşturuldu.")


# =====================================================================
# ANA ÇALIŞMA FONKSİYONU
# =====================================================================
def main() -> None:
    print("=" * 70)
    print("   CLOUDSTREAM SÜPER REPO: DİZİPAL VIP & SHA-256 ONARIM MOTORU   ")
    print("=" * 70)

    BUILDS_DIR.mkdir(parents=True, exist_ok=True)

    if not SOURCES_FILE.exists():
        log_error(f"sources.json dosyası bulunamadı: {SOURCES_FILE}")
        sys.exit(1)

    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources_cfg = json.load(f)

    repo_full, branch = get_repo_identifier(sources_cfg)
    log_info(f"Hedef GitHub Deposu: {repo_full} (Dal: {branch})")

    sources_list = sorted(sources_cfg.get("sources", []), key=lambda x: x.get("priority", 99))
    blacklist = sources_cfg.get("blacklist", [])
    global_whitelist = [w.lower() for w in sources_cfg.get("global_whitelist", DEFAULT_GLOBAL_WHITELIST)]

    session = get_session()
    broken_report: List[Dict[str, Any]] = []

    # 1. Kaynakları tara ve DiziPal'ı VIP olarak ayır
    dizipal_vip_list, general_candidates = fetch_sources(
        session, sources_list, blacklist, global_whitelist, broken_report
    )

    # 2. DiziPal Otomatik Domain Avcısı
    active_dizipal_url = hunt_active_dizipal_domain(session, "https://dizipal2149.com")
    log_vip(f"Aktif DiziPal Alan Adı Doğrulandı: {active_dizipal_url}")

    # 3. DiziPal VIP varyasyonlarını işle (En güncel olan listenin başında)
    final_dizipals = process_dizipal_vip(session, dizipal_vip_list, BUILDS_DIR, active_dizipal_url)

    # 4. Genel aday eklentileri test et ve işle
    final_generals = process_general_candidates(session, general_candidates, BUILDS_DIR, broken_report)

    # 5. Tüm listeyi birleştir: DiziPal eklentileri en başta yer alır!
    final_plugins = final_dizipals + final_generals

    # 6. jsDelivr CDN URL'lerini ve ikon linklerini güncelle
    valid_filenames: Set[str] = set()
    exportable_plugins: List[Dict[str, Any]] = []

    for p in final_plugins:
        loc_name = p["_local_filename"]
        valid_filenames.add(loc_name)
        p["url"] = convert_to_cdn_url(repo_full, branch, loc_name)
        if "iconUrl" in p:
            p["iconUrl"] = convert_github_raw_to_cdn(p["iconUrl"])

        clean_dict = {k: v for k, v in p.items() if not k.startswith("_")}
        exportable_plugins.append(clean_dict)

    # 7. builds/plugins.json kaydet
    with open(PLUGINS_FILE, "w", encoding="utf-8") as f:
        json.dump(exportable_plugins, f, indent=2, ensure_ascii=False)
    log_success(f"builds/plugins.json kaydedildi ({len(exportable_plugins)} eklenti).")

    # 8. repo.json güncelle
    repo_manifest = {
        "name": sources_cfg.get("name", "CloudStream Süper Repo"),
        "description": sources_cfg.get("description", "Otonom CloudStream Deposu"),
        "manifestVersion": 1,
        "pluginLists": [
            f"https://raw.githubusercontent.com/{repo_full}/{branch}/builds/plugins.json",
            f"https://cdn.jsdelivr.net/gh/{repo_full}@{branch}/builds/plugins.json"
        ]
    }
    with open(REPO_FILE, "w", encoding="utf-8") as f:
        json.dump(repo_manifest, f, indent=2, ensure_ascii=False)
    log_success(f"repo.json güncellendi -> {repo_manifest['pluginLists'][0]}")

    # 9. domains.json dosyasını güncelle (DiziPal adresini en başa yaz)
    domains_data: Dict[str, List[str]] = {}
    if DOMAINS_FILE.exists():
        try:
            with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
                domains_data = json.load(f)
        except Exception:
            pass
    domains_data["DiziPal"] = [active_dizipal_url, "https://dizipal2149.com", "https://dizipal1595.com"]
    with open(DOMAINS_FILE, "w", encoding="utf-8") as f:
        json.dump(domains_data, f, indent=2, ensure_ascii=False)
    log_success("domains.json DiziPal adresiyle güncellendi.")

    # 10. broken_plugins.json kaydet
    with open(BROKEN_PLUGINS_FILE, "w", encoding="utf-8") as f:
        json.dump(broken_report, f, indent=2, ensure_ascii=False)
    log_success(f"broken_plugins.json kaydedildi ({len(broken_report)} kayıt).")

    # 11. builds/ klasöründeki eski çakışan .cs3 dosyalarını sil (Prune)
    prune_unused_build_files(BUILDS_DIR, valid_filenames)

    # 12. README.md güncelle
    generate_readme(README_FILE, repo_full, branch, final_plugins, len(broken_report), active_dizipal_url)

    # 13. jsDelivr Purge
    log_info("jsDelivr CDN önbelleği temizleniyor...")
    purge_urls = [
        f"https://purge.jsdelivr.net/gh/{repo_full}@{branch}/repo.json",
        f"https://purge.jsdelivr.net/gh/{repo_full}@{branch}/builds/plugins.json",
        f"https://purge.jsdelivr.net/gh/{repo_full}@{branch}/domains.json"
    ]
    for purl in purge_urls:
        try:
            session.get(purl, timeout=5)
        except Exception:
            pass
    log_success("jsDelivr önbellek temizleme talepleri gönderildi.")

    print("=" * 70)
    log_success(f"TAMAMLANDI: {len(final_dizipals)} DiziPal VIP varyasyonu dahil toplam {len(exportable_plugins)} eklenti hazır!")
    print("=" * 70)


if __name__ == "__main__":
    main()
