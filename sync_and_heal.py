#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudStream Süper Repo: Akıllı TR Filtresi, Canlı Site Kontrolü ve Onarım Motoru
================================================================================
1. SADECE TÜRKÇE FİLTRESİ (Dil Ayıklama):
   - Eklentinin language değeri "tr" olanları veya Türkçe repolardan gelenleri kabul eder.
   - Phisher ve Megix (CSX) gibi global repolardan yalnızca popüler eklentileri
     (NetflixMirror, PrimeVideo, Disney, Twitch, YouTube vb.) alır; geri kalan yüzlerce
     Hintçe/Asya/yabancı eklentiyi eler.
2. GERÇEK SİTE CANLILIK TESTİ (Dead-Site Eliminator):
   - .cs3 dosyasının içindeki DEX dizgilerinden veya domains.json eşleşmesinden hedef site
     alan adını tespit eder.
   - Gerçek HTTP GET isteği ile sitenin canlı olup olmadığını test eder (Cloudflare/Timeout/404/502).
   - Kapanan sitelerin eklentilerini eler. Aynı sitenin kopyalarında (örn. DiziPal vs DiziPalOriginal)
     çalışmayan eski kopya elenir, çalışan sürüm ana eklenti olarak kalır.
3. BLACKLIST & RAPORLAMA:
   - sources.json içindeki blacklist'i uygular.
   - Elenen tüm eklentileri nedenleriyle birlikte broken_plugins.json raporuna yazar.
4. DİSK TEMİZLİĞİ (Prune):
   - builds/ klasöründeki gereksiz veya elenen tüm .cs3 dosyalarını silerek depoyu tertemiz tutar.
5. jsDelivr CDN & GitHub Senkronizasyonu.
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
from concurrent.futures import ThreadPoolExecutor, as_completed

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

# İstenmeyen harici genel sunucular (DEX içinde arama yapılırken filtrelenir)
IGNORE_HOSTS: Set[str] = {
    'schema.org', 'w3.org', 'github.com', 'google.com', 'android.com',
    'jsdelivr.net', 'cloudflare.com', 'raw.githubusercontent.com',
    'youtube.com', 't.me', 'telegram.org', 'discord.gg', 'tmdb.org',
    'themoviedb.org', 'opensubtitles.org', 'imdb.com', 'facebook.com',
    'twitter.com', 'instagram.com', 'example.com', 'wikipedia.org',
    'repo.json', 'plugins.json', 'googlevideo.com', 'gstatic.com',
    'ornekadres.com', 'inv.nadeko.net', 'invidious.nerdvpn.de', 'invidious.f5.si'
}

# Kesin filtrelenecek yabancı diller
FOREIGN_LANGUAGES: Set[str] = {
    "hi", "zh", "ta", "te", "bn", "id", "de", "fr", "pt-br", "fil", "pl", "ko", "mx", "ar", "es"
}

# Global repolardan sadece kabul edilecek anahtar kelimeler
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


def log_anti_break(msg: str) -> None:
    print(f"\033[95m[ANTI-BREAK]\033[0m {msg}", flush=True)


def log_elim(msg: str) -> None:
    print(f"\033[33m[ELENDİ]\033[0m {msg}", flush=True)


def log_domain(msg: str) -> None:
    print(f"\033[96m[DOMAİN]\033[0m {msg}", flush=True)


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
    return f"sha256-{hasher.hexdigest()}"


def sanitize_filename(name: str) -> str:
    cleaned = re.sub(r'[^\w\-_\.]', '_', name)
    cleaned = re.sub(r'_+', '_', cleaned).strip('_')
    return cleaned or "plugin"


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
# SİTE ADI NORMALİZASYONU & DOMAİN TESPİTİ
# =====================================================================
def normalize_site_key(name: str, internal_name: str) -> str:
    """
    Aynı sitenin kopyalarını (DiziPal vs DiziPalOriginal vs DiziPal_Ripplay)
    ortak bir grupta toplamak için kök site adını belirler.
    """
    raw = name.split('[')[0].strip()
    raw = re.sub(r'Provider$', '', raw, flags=re.I)
    raw = re.sub(r'Plugin$', '', raw, flags=re.I)
    clean = re.sub(r'[^a-zA-Z0-9]', '', raw).lower()

    # Bilinen çoklu varyasyon ön ekleri
    known_prefixes = [
        "dizipal", "dizibox", "belgeselx", "hdfilmcehennemi", "ddizi",
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
    """
    .cs3 ZIP arşivinin içindeki classes.dex dosyasından hedef web sitesinin
    alan adını tespit eder.
    """
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


def check_site_alive(session: requests.Session, host: Optional[str], active_domains_map: Dict[str, List[str]]) -> Tuple[bool, str]:
    """
    Hedef web sitesine canlılık testi yapar:
    - HTTP GET isteği gönderir (Cloudflare / User-Agent ile).
    - 200, 301, 302, 403 (Cloudflare koruması altında olduğunu ve sunucunun açık olduğunu gösterir) durumlarını canlı kabul eder.
    - 404, 500, 502, NXDOMAIN veya zaman aşımı durumunda kapalı sayar.
    """
    if not host:
        return True, "Dahili sağlayıcı / Doğrudan akış"

    # Önce domains.json içinde güncel bir yönlendirme adresi var mı kontrol et
    clean_host = host.lower()
    for site_k, ulist in active_domains_map.items():
        if clean_host in site_k.lower() or any(clean_host in u.lower() for u in ulist):
            if ulist:
                parsed = urllib.parse.urlparse(ulist[0])
                if parsed.netloc:
                    host = parsed.netloc

    for proto in ["https://", "http://"]:
        try:
            target_url = f"{proto}{host}"
            resp = session.get(target_url, timeout=6, allow_redirects=True)
            if resp.status_code in [200, 301, 302, 307, 308, 403]:
                return True, f"Canlı (HTTP {resp.status_code})"
            if resp.status_code in [404, 500, 502, 503]:
                return False, f"Sunucu hatası (HTTP {resp.status_code})"
        except requests.exceptions.SSLError:
            # SSL hatası genelde sunucunun açık olduğunu gösterir
            return True, "Canlı (SSL Aktif)"
        except Exception:
            pass

    return False, "Erişim hatası / Alan adı kapalı / Zaman aşımı"


# =====================================================================
# ADIM 1: KAYNAKLARDAN ÇEKME & DİL AYIKLAMA (SADECE TÜRKÇE)
# =====================================================================
def fetch_and_filter_sources(
    session: requests.Session,
    sources_list: List[Dict[str, Any]],
    blacklist: List[str],
    global_whitelist: List[str],
    broken_report: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    1. Sadece Türkçe eklentileri veya Türkçe repoları kabul eder.
    2. Global repolardan sadece whitelist eklentileri (Netflix, Prime vb.) alır.
    3. Blacklist'teki eklentileri doğrudan eler.
    """
    accepted_plugins: List[Dict[str, Any]] = []

    for src in sources_list:
        if not src.get("enabled", True):
            continue

        name = src.get("name", "Bilinmeyen")
        url = src.get("url", "")
        priority = src.get("priority", 99)
        src_lang = src.get("language", "tr")

        is_global_source = (src_lang not in ["tr", "all"]) or ("phisher" in url.lower()) or ("csx" in url.lower())

        log_info(f"[{name}] Taranıyor (Öncelik: {priority}, Global={is_global_source}) -> {url}")
        try:
            resp = session.get(url, timeout=HTTP_TIMEOUT)
            if resp.status_code != 200:
                log_warn(f"[{name}] repo.json alınamadı (HTTP {resp.status_code})")
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

                        # 1. Kara liste kontrolü
                        if in_name in blacklist or item_name in blacklist:
                            log_elim(f"[{name}] Kara listede: {item_name}")
                            broken_report.append({
                                "name": item_name,
                                "internalName": in_name,
                                "source": name,
                                "version": item.get("version"),
                                "reason": "Kara liste (Blacklist) engeli"
                            })
                            continue

                        # 2. Global Repo kontrolü: Sadece popüler whitelist eklentiler alınır
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

                        # 3. Türkçe repolardaki yabancı dillerin ayıklanması
                        if item_lang in FOREIGN_LANGUAGES:
                            broken_report.append({
                                "name": item_name,
                                "internalName": in_name,
                                "source": name,
                                "version": item.get("version"),
                                "reason": f"Yabancı dil filtresi ({item_lang})"
                            })
                            continue

                        enriched = dict(item)
                        enriched["_source_name"] = name
                        enriched["_source_priority"] = priority
                        accepted_plugins.append(enriched)

                except Exception as e:
                    log_warn(f"[{name}] Liste ayrıştırma hatası ({p_list_url}): {e}")

        except Exception as e:
            log_error(f"[{name}] Kaynak tarama hatası: {e}")

    log_success(f"Dil filtresi sonrası aday eklenti sayısı: {len(accepted_plugins)}")
    return accepted_plugins


# =====================================================================
# ADIM 2 & 3: CANLI SİTE TESTİ & TEKİL SAĞLAM EKLENTİ SEÇİMİ
# =====================================================================
def download_candidate_cs3(session: requests.Session, plugin: Dict[str, Any], builds_dir: Path) -> Optional[Path]:
    """Eklentinin .cs3 dosyasını indirir veya yerelde varsa doğrular."""
    raw_name = plugin.get("internalName") or plugin.get("name") or "plugin"
    fname = f"{sanitize_filename(raw_name)}.cs3"
    target_path = builds_dir / fname

    remote_url = plugin.get("url", "")
    if remote_url:
        try:
            resp = session.get(remote_url, timeout=HTTP_TIMEOUT, stream=True)
            if resp.status_code == 200:
                content = resp.content
                if len(content) >= MIN_VALID_CS3_SIZE:
                    with open(target_path, "wb") as f:
                        f.write(content)
                    return target_path
        except Exception:
            pass

    if target_path.exists() and target_path.stat().st_size >= MIN_VALID_CS3_SIZE:
        return target_path

    return None


def evaluate_and_deduplicate(
    session: requests.Session,
    candidates: List[Dict[str, Any]],
    builds_dir: Path,
    active_domains_map: Dict[str, List[str]],
    broken_report: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    1. Aday eklentileri aynı sitenin varyasyonlarına göre gruplar (örn. DiziPal).
    2. .cs3 içindeki hedef domaini canlılık testine tabi tutar.
    3. Kapanan sitelerin kopyalarını eler.
    4. Canlı çalışan en güncel ve en yüksek öncelikli TEK sürümü ana eklenti seçer.
    """
    log_info("Aday eklentiler indiriliyor ve canlılık analizleri yapılıyor...")

    # Gruplama
    site_groups: Dict[str, List[Dict[str, Any]]] = {}
    for p in candidates:
        key = normalize_site_key(p.get("name", ""), p.get("internalName", ""))
        site_groups.setdefault(key, []).append(p)

    log_info(f"Toplam {len(site_groups)} farklı site grubu tespit edildi.")

    final_selected_plugins: List[Dict[str, Any]] = []

    def test_single_plugin(p: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[Path], bool, str]:
        path = download_candidate_cs3(session, p, builds_dir)
        if not path:
            return p, None, False, "Dosya indirilemedi / Bozuk CS3"

        # Canlı TV / IPTV eklentileri doğrudan akış sağladığı için her zaman canlıdır
        if "Live" in p.get("tvTypes", []):
            return p, path, True, "Canlı TV / IPTV Akışı"

        # DEX içinden hedef domaini bul ve test et
        host = extract_domain_from_cs3(path)
        is_alive, reason = check_site_alive(session, host, active_domains_map)
        return p, path, is_alive, f"Domain: {host or 'Dahili'} ({reason})"

    for group_key, plist in site_groups.items():
        # Sürüm ve önceliğe göre sırala (en güncel sürüm en üstte)
        sorted_plist = sorted(
            plist,
            key=lambda x: (int(x.get("version", 0) or 0), -int(x.get("_source_priority", 99))),
            reverse=True
        )

        working_winner: Optional[Dict[str, Any]] = None
        winner_path: Optional[Path] = None

        with ThreadPoolExecutor(max_workers=min(len(sorted_plist), 8)) as executor:
            tested_results = list(executor.map(test_single_plugin, sorted_plist))

        for p_item, p_path, is_alive, reason_msg in tested_results:
            if is_alive and p_path:
                if working_winner is None:
                    working_winner = p_item
                    winner_path = p_path
                else:
                    # Aynı sitenin diğer sağlam kopyaları da elenir; tek ve temiz ana sürüm kalır
                    broken_report.append({
                        "name": p_item.get("name"),
                        "internalName": p_item.get("internalName"),
                        "source": p_item.get("_source_name"),
                        "version": p_item.get("version"),
                        "reason": f"Daha güncel/çalışan versiyonu seçildi ({working_winner.get('name')} v{working_winner.get('version')})"
                    })
            else:
                broken_report.append({
                    "name": p_item.get("name"),
                    "internalName": p_item.get("internalName"),
                    "source": p_item.get("_source_name"),
                    "version": p_item.get("version"),
                    "reason": f"Hedef site kapalı / ulaşılamıyor ({reason_msg})"
                })

        if working_winner and winner_path:
            # Temizleme ve ad düzeltme
            clean_winner = dict(working_winner)
            clean_winner["fileSize"] = winner_path.stat().st_size
            clean_winner["fileHash"] = compute_sha256(winner_path)
            clean_winner["_local_filename"] = winner_path.name

            # DiziPalOriginal adını daha şık bir isimle sunalım
            if clean_winner.get("internalName") == "DiziPalOriginal":
                clean_winner["name"] = "DiziPal (Orijinal)"

            final_selected_plugins.append(clean_winner)
            log_success(f"[SEÇİLDİ] {clean_winner.get('name')} (v{clean_winner.get('version')}, {clean_winner.get('_source_name')})")

    return final_selected_plugins


# =====================================================================
# ADIM 4: GEREKSİZ CS3 DOSYALARINI DİSKTEN TEMİZLEME (PRUNE)
# =====================================================================
def prune_unused_build_files(builds_dir: Path, valid_filenames: Set[str]) -> int:
    """
    builds/ klasöründe bulunan ancak nihai temiz listede yer almayan
    tüm yabancı ve elenmiş .cs3 dosyalarını siler.
    """
    deleted_count = 0
    if not builds_dir.exists():
        return 0

    for file_path in builds_dir.glob("*.cs3"):
        if file_path.name not in valid_filenames:
            try:
                os.remove(file_path)
                deleted_count += 1
            except Exception as e:
                log_warn(f"Dosya silinemedi ({file_path.name}): {e}")

    log_success(f"Diskten {deleted_count} adet gereksiz/yabancı .cs3 dosyası temizlendi.")
    return deleted_count


# =====================================================================
# ADIM 5: README & RAPOR OLUŞTURUCU
# =====================================================================
def generate_readme(
    readme_path: Path,
    repo_full: str,
    branch: str,
    final_plugins: List[Dict[str, Any]],
    broken_count: int,
    sources_stats: List[Dict[str, Any]]
) -> None:
    now_utc = datetime.now(timezone.utc)
    now_tr = now_utc + timedelta(hours=3)
    formatted_time = now_tr.strftime("%d.%m.%Y - %H:%M:%S (TSİ / GMT+3)")

    super_repo_url = f"https://cdn.jsdelivr.net/gh/{repo_full}@{branch}/repo.json"

    lines = [
        "# ⚡ CloudStream Süper Repo (Otonom & Canlı Site Korumalı)",
        "",
        "> **En güncel Türkçe ve popüler global CloudStream eklentilerini (.cs3) tek bir adreste toplayan,**",
        "> **bozuk kopyaları ve yabancı dilleri otomatik eleyen, Türkiye İSS/BTK engellerine takılmayan süper repo.**",
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
        f"- 📦 **Aktif ve Çalışan Eklenti:** `{len(final_plugins)}` adet (Öz Türkçe & Popüler Global)",
        f"- 🗑️ **Elenen Bozuk / Yabancı Eklenti:** `{broken_count}` adet ([broken_plugins.json](broken_plugins.json))",
        f"- 🛡️ **Canlı Site Doğrulaması:** `Aktif (Dead-Site Eliminator)`",
        f"- ⚡ **CDN Hızlandırma:** `jsDelivr Global Edge Network`",
        "",
        "### 📚 Kaynak Repolar",
        "",
        "| Öncelik | Kaynak Repo | Dil | Durum |",
        "|:---:|:---|:---:|:---:|",
    ]

    for stat in sources_stats:
        status_badge = "🟢 Aktif" if stat["active"] else "🔴 Ulaşılamadı"
        lines.append(f"| **{stat['priority']}** | [{stat['name']}]({stat['url']}) | `{stat['language']}` | {status_badge} |")

    lines.extend([
        "",
        "---",
        "",
        "## 🌟 Akıllı Filtreleme Özellikleri",
        "",
        "1. **🇹🇷 Sadece Türkçe & Popüler Global Filtresi:**",
        "   Yüzlerce Hintçe, Çince, Rusça eklenti tamamen temizlenmiş; yalnızca Türkiye'de çalışan dizi/film/spor eklentileri ile popüler servisler (Netflix, Prime, Disney, Twitch vb.) depoya dahil edilmiştir.",
        "",
        "2. **🔍 Gerçek Site Canlılık Testi (Dead-Site Eliminator):**",
        "   Eklentilerin hedef aldığı internet siteleri gerçek HTTP GET istekleriyle taranır. Kapanan veya eski alan adına sahip eklentiler (örneğin eski DiziPal kopyası) otomatik elenir; yalnızca çalışan güncel eklenti (DiziPal Orijinal) depoda kalır.",
        "",
        "3. **🛡️ Otomatik Blacklist & Raporlama:**",
        "   Terk edilmiş veya bozuk kopyalar otomatik olarak kara listeye alınır ve elenen tüm eklentiler `broken_plugins.json` raporuna yazılır.",
        "",
        "---",
        "",
        "## 📦 Aktif Eklentiler Listesi",
        "",
        f"<details open><summary><b>Toplam {len(final_plugins)} Çalışan Eklentiyi Göster</b></summary>",
        "",
        "| Eklenti Adı | Sürüm | Dil | Kaynak | Dosya Boyutu |",
        "|:---|:---:|:---:|:---|:---:|",
    ])

    sorted_plugins = sorted(final_plugins, key=lambda x: x.get("name", "").lower())
    for p in sorted_plugins:
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
        "## ⚙️ Otomasyon",
        "",
        "Bu repo GitHub Actions ile **her 6 saatte bir** (`0 */6 * * *`) otomatik olarak güncellenir,",
        "canlılık testleri yapılır ve jsDelivr CDN önbelleği temizlenir.",
        "",
        "_Otomatik olarak üretilmiştir._"
    ])

    with open(readme_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log_success("README.md dosyası oluşturuldu.")


# =====================================================================
# ANA ÇALIŞMA FONKSİYONU
# =====================================================================
def main() -> None:
    print("=" * 70)
    print("   CLOUDSTREAM SÜPER REPO: AKILLI TR & CANLI SİTE ONARIM MOTORU   ")
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
    domain_source_url = sources_cfg.get("domain_source_url", "")

    session = get_session()

    # Mevcut domains.json dosyasını yükle
    active_domains_map: Dict[str, List[str]] = {}
    if DOMAINS_FILE.exists():
        try:
            with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
                active_domains_map = json.load(f)
        except Exception:
            pass

    broken_report: List[Dict[str, Any]] = []

    # 1. Kaynakları tara ve Dil Filtresini uygula (Sadece Türkçe ve Popüler Global)
    candidate_plugins = fetch_and_filter_sources(
        session, sources_list, blacklist, global_whitelist, broken_report
    )

    # 2. Canlı Site Testi ve Tekil Eklenti Seçimi (Dead-Site Eliminator & Dedup)
    final_plugins = evaluate_and_deduplicate(
        session, candidate_plugins, BUILDS_DIR, active_domains_map, broken_report
    )

    # 3. URL'leri jsDelivr formatına çevir
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

    # 4. builds/plugins.json kaydet
    with open(PLUGINS_FILE, "w", encoding="utf-8") as f:
        json.dump(exportable_plugins, f, indent=2, ensure_ascii=False)
    log_success(f"builds/plugins.json kaydedildi ({len(exportable_plugins)} öz ve sağlam eklenti).")

    # 5. repo.json güncelle
    repo_manifest = {
        "name": sources_cfg.get("name", "CloudStream Süper Repo"),
        "description": sources_cfg.get("description", "Otonom CloudStream Deposu"),
        "manifestVersion": 1,
        "pluginLists": [
            f"https://cdn.jsdelivr.net/gh/{repo_full}@{branch}/builds/plugins.json"
        ]
    }
    with open(REPO_FILE, "w", encoding="utf-8") as f:
        json.dump(repo_manifest, f, indent=2, ensure_ascii=False)
    log_success(f"repo.json güncellendi -> {repo_manifest['pluginLists'][0]}")

    # 6. broken_plugins.json kaydet
    with open(BROKEN_PLUGINS_FILE, "w", encoding="utf-8") as f:
        json.dump(broken_report, f, indent=2, ensure_ascii=False)
    log_success(f"broken_plugins.json kaydedildi ({len(broken_report)} elenen/bozuk kayıt).")

    # 7. builds/ klasöründeki gereksiz .cs3 dosyalarını sil (Disk Prune)
    prune_unused_build_files(BUILDS_DIR, valid_filenames)

    # 8. README.md güncelle
    sources_stats = [
        {
            "name": s.get("name"),
            "url": s.get("url"),
            "priority": s.get("priority"),
            "language": s.get("language", "tr"),
            "active": True
        }
        for s in sources_list
    ]
    generate_readme(README_FILE, repo_full, branch, final_plugins, len(broken_report), sources_stats)

    # 9. jsDelivr Purge
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
    log_success(f"İŞLEM TAMAMLANDI: {len(exportable_plugins)} adet çalışan eklenti hazırlandı!")
    print("=" * 70)


if __name__ == "__main__":
    main()
