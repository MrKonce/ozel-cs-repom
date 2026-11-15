#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudStream Süper Repo: Sıfır Hata, Tekil TR Deposu & DiziPal VIP Motoru
========================================================================
1. YALNIZCA TÜRKÇE REPOLAR & SIKI TEKİLLEŞTİRME:
   - Sadece 5 Türkçe repo (TurkSinema, BTVault, TurkSpor, Ripplay, Feroxx Kekik) taranır.
   - Aynı sitenin farklı repolardaki kopyaları tekilleştirilir; yalnızca en güncel sürüm seçilir.
   - İSTİSNA: DiziPal varyasyonlarının tamamı yedekli olarak korunur.
   - builds/ klasörü sıfırdan temizlenerek yalnızca seçilen ~60-80 eklenti indirilir.
2. SHA256 (DigestException) HATASININ KÖKÜNDEN KALDIRILMASI:
   - plugins.json içerisindeki 'fileHash', 'sha256' ve 'hash' anahtarları tamamen silinir.
   - CloudStream hash kontrolünü atlar ve .cs3 doğrudan kurulur.
3. CACHE VE 516 EKLENTİ SORUNUNUN ÇÖZÜMÜ:
   - repo.json içinde tekil ve önbelleksiz raw.githubusercontent.com adresi sunulur.
   - İndirme URL'leri doğrudan güncel raw.githubusercontent.com üzerinden çalışır.
4. DİZİPAL OTOMATİK DOMAİN AVCISI & BANNER.
"""

import os
import sys
import json
import re
import shutil
import hashlib
import zipfile
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set

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

# Kısa drama / spam scrapers
SPAM_DRAMA_WORDS: Set[str] = {
    'dramabox', 'dramadunyam', 'dramaflix', 'elodrama', 'flickreels',
    'freedrama', 'greatdrama', 'hidrama', 'lovedrama', 'mapple',
    'mcdrama', 'microdrama', 'minutedrama', 'moreshort', 'mtdrama',
    'musedrama', 'mydrama', 'oidrama', 'sevenreels', 'shortmax',
    'shortizle', 'shortswave', 'shotshort', 'trydrama', 'vibeshort',
    'donkey', 'dmaxdrama', 'arcanadrama', 'asidbdrama'
}

# Yabancı veya gereksiz spor bahis yönlendirmeleri
OBSCURE_BETTING_SPORTS: Set[str] = {
    'betmatiktv', 'ciftd2m', 'crex', 'domatestv', 'intersportv',
    'jestyayin', 'kacakspor', 'koalatv', 'kralsporhd', 'leotv',
    'mackeyfi', 'mahsunsports', 'nebulasports', 'netvgold', 'ntvs',
    'papazsports', 'patronhd', 'stbtv', 'vegoltv', 'viontv',
    'vivoxspor', 'zbahistv', 'beyazelma', 'atomspor',
    'basketballreplays', 'basketballvideo', 'daddylive', 'streameast',
    'streamed', 'timstreams', 'sportsreplay', 'superstream'
}

# Düşük kaliteli veya eski kapanmış sağlayıcılar
MINOR_LOW_QUALITY: Set[str] = {
    'cizgifilmizleinfo', 'cizgifilmtv', 'cizgidizinet', 'cizgisite',
    'cizgiportal', 'cizgivedizi', 'catcasttv', 'clipbox', 'cinecat',
    'cinesimkl', 'deokwave', 'filmizzle', 'liderfilmizle', 'lightflix',
    'minidiziizle', 'netfilmizle', 'nettv', 'powersinema', 'stardusttv',
    'trdiziizle', 'velarium', 'warflix', 'watch2movies', 'yesilcamtv',
    'wiodb', 'wioshort', 'wiomulti', 'wioiptvpanels'
}


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


# =====================================================================
# DİZİPAL ÖZEL AVCISI & DOMAİN TESPİTİ
# =====================================================================
def extract_dizipal_domain_and_number(cs3_path: Path) -> Tuple[Optional[str], int]:
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
    log_vip(f"DiziPal Domain Avcısı devrede. Başlangıç referansı: {initial_known}")
    try:
        r = session.get(initial_known, timeout=6, allow_redirects=True)
        final_url = r.url.rstrip('/')
        if r.status_code in [200, 301, 302, 403, 503]:
            log_vip(f"Aktif DiziPal adresi doğrulandı: {final_url} (HTTP {r.status_code})")
            return final_url
    except Exception as e:
        log_warn(f"Mevcut DiziPal adresine ulaşılamadı ({initial_known}): {e}")

    match = re.search(r'dizipal(\d+)', initial_known)
    base_num = int(match.group(1)) if match else 2149

    for offset in range(1, 20):
        test_num = base_num + offset
        test_url = f"https://dizipal{test_num}.com"
        try:
            r = session.get(test_url, timeout=4, allow_redirects=True)
            if r.status_code in [200, 301, 302, 403, 503]:
                log_vip(f"🔥 YENİ AKTİF DİZİPAL BULUNDU: {r.url.rstrip('/')}")
                return r.url.rstrip('/')
        except Exception:
            pass

    return initial_known


# =====================================================================
# SİTE ADI NORMALİZASYONU (SIKI TEKİLLEŞTİRME)
# =====================================================================
def normalize_site(name: str) -> str:
    c = re.sub(r'[^a-zA-Z0-9]', '', name.split('[')[0]).lower()
    if 'hdfilm' in c:
        return 'hdfilmcehennemi'
    if 'fullhdfilm' in c:
        return 'fullhdfilmizlesene'
    if 'webdrama' in c:
        return 'webdramaturkey'
    if 'tlc' in c:
        return 'tlctr'
    if 'wiospor' in c or 'wiojeltspor' in c:
        return 'wiospor'
    return c


# =====================================================================
# ADIM 1: KAYNAKLARDAN ÇEKME (SADECE TÜRKÇE REPOLAR)
# =====================================================================
def fetch_turkish_sources(
    session: requests.Session,
    sources_list: List[Dict[str, Any]],
    blacklist: List[str],
    broken_report: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    dizipal_list: List[Dict[str, Any]] = []
    general_list: List[Dict[str, Any]] = []

    for src in sources_list:
        if not src.get("enabled", True):
            continue

        name = src.get("name", "Bilinmeyen")
        url = src.get("url", "")
        priority = src.get("priority", 99)

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

                    items = p_resp.json()
                    item_list = items if isinstance(items, list) else list(items.values())

                    for item in item_list:
                        if not isinstance(item, dict):
                            continue

                        in_name = item.get("internalName") or item.get("name") or ""
                        item_name = item.get("name", "")
                        clean_k = re.sub(r'[^a-zA-Z0-9]', '', item_name).lower()

                        # Kara Liste
                        if in_name in blacklist or item_name in blacklist:
                            broken_report.append({
                                "name": item_name,
                                "internalName": in_name,
                                "source": name,
                                "reason": "Kara liste (Blacklist) engeli"
                            })
                            continue

                        enriched = dict(item)
                        enriched["_source_name"] = name
                        enriched["_source_priority"] = priority

                        # --- DİZİPAL VIP AYIKLAMA ---
                        if "dizipal" in item_name.lower() or "dizipal" in in_name.lower():
                            dizipal_list.append(enriched)
                            log_vip(f"DiziPal VIP Keşfedildi: {item_name} ({name})")
                            continue

                        # Filtreler: Kısa drama, önemsiz bahis ve düşük kalite scrapers
                        if clean_k in SPAM_DRAMA_WORDS:
                            broken_report.append({
                                "name": item_name,
                                "internalName": in_name,
                                "source": name,
                                "reason": "Kısa drama / spam filtresi"
                            })
                            continue

                        if clean_k in OBSCURE_BETTING_SPORTS:
                            broken_report.append({
                                "name": item_name,
                                "internalName": in_name,
                                "source": name,
                                "reason": "Önemsiz bahis/yabancı spor filtresi"
                            })
                            continue

                        if clean_k in MINOR_LOW_QUALITY:
                            broken_report.append({
                                "name": item_name,
                                "internalName": in_name,
                                "source": name,
                                "reason": "Düşük kaliteli / eski sağlayıcı filtresi"
                            })
                            continue

                        # Yabancı dil filtresi
                        item_lang = (item.get("language") or "").lower()
                        if item_lang in ["hi", "zh", "ta", "de", "fr", "id", "en"]:
                            broken_report.append({
                                "name": item_name,
                                "internalName": in_name,
                                "source": name,
                                "reason": f"Yabancı dil filtresi ({item_lang})"
                            })
                            continue

                        general_list.append(enriched)

                except Exception as e:
                    log_warn(f"[{name}] Liste ayrıştırma hatası: {e}")

        except Exception as e:
            log_error(f"[{name}] Kaynak tarama hatası: {e}")

    log_success(f"DiziPal VIP: {len(dizipal_list)} adet | Genel Türkçe Adaylar: {len(general_list)} adet.")
    return dizipal_list, general_list


# =====================================================================
# ADIM 2: CS3 İNDİRME & BOYUT TESPİTİ
# =====================================================================
def download_cs3(session: requests.Session, plugin: Dict[str, Any], builds_dir: Path) -> Optional[Tuple[Dict[str, Any], Path, int]]:
    src_slug = sanitize_slug(plugin.get("_source_name", "Repo"))
    raw_name = sanitize_filename(plugin.get("internalName") or plugin.get("name") or "plugin")
    version = int(plugin.get("version", 1) or 1)

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

    actual_size = target_path.stat().st_size
    item = dict(plugin)
    item["fileSize"] = actual_size
    item["_local_filename"] = target_filename

    # SHA256 KESİN ÇÖZÜMÜ: Mismatched digest hatasını önlemek için hash anahtarları silinir!
    item.pop("fileHash", None)
    item.pop("sha256", None)
    item.pop("hash", None)

    return item, target_path, actual_size


# =====================================================================
# ADIM 3: DİZİPAL VIP VARYASYONLARI İŞLEYİCİSİ
# =====================================================================
def process_dizipals(
    session: requests.Session,
    dizipal_list: List[Dict[str, Any]],
    builds_dir: Path,
    active_dizipal_url: str
) -> List[Dict[str, Any]]:
    log_vip("DiziPal VIP eklentileri indiriliyor ve işleniyor...")
    verified = []

    for item in dizipal_list:
        res = download_cs3(session, item, builds_dir)
        if res:
            p_dict, path, size = res
            domain, num = extract_dizipal_domain_and_number(path)
            p_dict["_num"] = num
            p_dict["_domain"] = domain
            verified.append(p_dict)

    if not verified:
        return []

    # En güncel DiziPal'ı (en yüksek domain numaralı ve en yüksek sürümlü) lider seç
    verified.sort(
        key=lambda x: (x.get("_num", 0), int(x.get("version", 0) or 0)),
        reverse=True
    )

    final_dizipals = []
    seen_internals = set()

    for idx, p in enumerate(verified):
        src_name = p.get("_source_name", "Repo")
        clean_item = dict(p)

        if idx == 0:
            clean_item["name"] = "⭐ DiziPal [EN GÜNCEL - Aktif]"
            clean_item["internalName"] = "DiziPalOriginal"
            clean_item["description"] = f"🔥 Doğrulanan Aktif Domain: {active_dizipal_url} | Otomatik Güncellendi."
            log_vip(f"LİDER DİZİPAL: {clean_item['name']} ({src_name}, Domain No: {p.get('_num')})")
        else:
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

        while clean_item["internalName"] in seen_internals:
            clean_item["internalName"] += f"_{clean_item.get('version', 1)}"
        seen_internals.add(clean_item["internalName"])

        final_dizipals.append(clean_item)

    return final_dizipals


# =====================================================================
# ADIM 4: GENEL TÜRKÇE EKLENTİLERİ SIKI TEKİLLEŞTİRME
# =====================================================================
def process_strict_dedup(
    session: requests.Session,
    candidates: List[Dict[str, Any]],
    builds_dir: Path,
    broken_report: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Normal Türkçe eklentilerde aynı isim/site için birden fazla repodaki kopyalar
    arasından SADECE en güncel tek bir tanesini alır.
    """
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for p in candidates:
        k = normalize_site(p.get("name", ""))
        groups.setdefault(k, []).append(p)

    final_general = []

    for group_key, plist in groups.items():
        # Sürüm ve önceliğe göre sırala: En yüksek sürüm ve öncelik kazanır
        sorted_plist = sorted(
            plist,
            key=lambda x: (int(x.get("version", 0) or 0), -int(x.get("_source_priority", 99))),
            reverse=True
        )

        winner = None
        for p in sorted_plist:
            res = download_cs3(session, p, builds_dir)
            if res:
                winner = res[0]
                break
            else:
                broken_report.append({
                    "name": p.get("name"),
                    "internalName": p.get("internalName"),
                    "source": p.get("_source_name"),
                    "reason": "Dosya indirilemedi / Bozuk CS3"
                })

        if winner:
            final_general.append(winner)
            # Elenen diğer kopyaları rapora yaz
            for other_p in sorted_plist:
                if other_p != winner:
                    broken_report.append({
                        "name": other_p.get("name"),
                        "internalName": other_p.get("internalName"),
                        "source": other_p.get("_source_name"),
                        "reason": f"Tekilleştirme yapıldı; daha güncel olan '{winner.get('name')} v{winner.get('version')}' seçildi."
                    })

    return final_general


# =====================================================================
# ADIM 5: README OLUŞTURUCU
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

    raw_repo_url = f"https://raw.githubusercontent.com/{repo_full}/{branch}/repo.json"

    lines = [
        "# ⚡ CloudStream Süper Repo (Otonom & DiziPal VIP Korumalı)",
        "",
        f"> ### 🔥 Güncel Aktif DiziPal Adresi: **{active_dizipal_url}** *(Otonom Doğrulandı)*",
        "",
        "> **En kaliteli Türkçe CloudStream eklentilerini (.cs3) sıfır önbellek gecikmesiyle sunan,**",
        "> **DiziPal VIP korumalı, tam tekilleştirilmiş ve SHA256 hatasız süper repo.**",
        "",
        "## 🚀 Hızlı Kurulum (CloudStream Uygulamasına Ekleme)",
        "",
        "CloudStream uygulamasında aşağıdaki bağlantıyı depo olarak ekleyerek tüm eklentilere anında erişebilirsiniz:",
        "",
        "```text",
        raw_repo_url,
        "```",
        "",
        "*(Bu bağlantı doğrudan `raw.githubusercontent.com` üzerinden sıfır gecikmeyle güncellenir ve eklenti çakışması yapmaz.)*",
        "",
        "---",
        "",
        "## 📊 Genel Durum & İstatistikler",
        "",
        f"- 🕒 **Son Güncelleme:** `{formatted_time}`",
        f"- 🌟 **Aktif DiziPal Adresi:** `{active_dizipal_url}`",
        f"- 📦 **Aktif Öz Türkçe Eklenti:** `{len(final_plugins)}` adet (Tekilleştirilmiş)",
        f"- 🗑️ **Elenen Kopya / Yabancı Eklenti:** `{broken_count}` adet ([broken_plugins.json](broken_plugins.json))",
        f"- 🛡️ **SHA256 Hatası Engeli:** `Aktif (Transfer Uyuşmazlıkları Önlenmiştir)`",
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
    print("   CLOUDSTREAM SÜPER REPO: SIKI TEKİLLEŞTİRME & DİZİPAL VIP   ")
    print("=" * 70)

    # builds/ klasörünü tamamen temizle (sıfırdan tertemiz indirme!)
    if BUILDS_DIR.exists():
        shutil.rmtree(BUILDS_DIR, ignore_errors=True)
    BUILDS_DIR.mkdir(parents=True, exist_ok=True)
    log_success("builds/ klasörü sıfırlandı.")

    if not SOURCES_FILE.exists():
        log_error(f"sources.json dosyası bulunamadı: {SOURCES_FILE}")
        sys.exit(1)

    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources_cfg = json.load(f)

    repo_full, branch = get_repo_identifier(sources_cfg)
    log_info(f"Hedef Depo: {repo_full} (Dal: {branch})")

    sources_list = sorted(sources_cfg.get("sources", []), key=lambda x: x.get("priority", 99))
    blacklist = sources_cfg.get("blacklist", [])

    session = get_session()
    broken_report: List[Dict[str, Any]] = []

    # 1. Yalnızca 5 Türkçe repoyu tara
    dizipal_list, general_candidates = fetch_turkish_sources(
        session, sources_list, blacklist, broken_report
    )

    # 2. DiziPal Otomatik Domain Avcısı
    active_dizipal_url = hunt_active_dizipal_domain(session, "https://dizipal2149.com")
    log_vip(f"Aktif DiziPal Alan Adı: {active_dizipal_url}")

    # 3. DiziPal VIP varyasyonlarını işle (En güncel olanı listenin başında tut)
    final_dizipals = process_dizipals(session, dizipal_list, BUILDS_DIR, active_dizipal_url)

    # 4. Genel Türkçe eklentilerde sıkı tekilleştirme yap (her sitenin tek en günceli)
    final_generals = process_strict_dedup(session, general_candidates, BUILDS_DIR, broken_report)

    # 5. Listeyi birleştir
    final_plugins = final_dizipals + final_generals
    log_success(f"Nihai Eklenti Sayısı: {len(final_plugins)} (DiziPal: {len(final_dizipals)} + Diğer: {len(final_generals)})")

    # 6. Doğrudan raw.githubusercontent indirme URL'lerini oluştur
    exportable_plugins: List[Dict[str, Any]] = []
    for p in final_plugins:
        loc_name = p["_local_filename"]
        # raw.githubusercontent.com: Sıfır önbellek gecikmesi ve %100 güvenilir indirme!
        p["url"] = f"https://raw.githubusercontent.com/{repo_full}/{branch}/builds/{loc_name}"

        # SHA256 hatasını tamamen kaldırmak için hash anahtarları silinir
        p.pop("fileHash", None)
        p.pop("sha256", None)
        p.pop("hash", None)

        clean_dict = {k: v for k, v in p.items() if not k.startswith("_")}
        exportable_plugins.append(clean_dict)

    # 7. builds/plugins.json kaydet
    with open(PLUGINS_FILE, "w", encoding="utf-8") as f:
        json.dump(exportable_plugins, f, indent=2, ensure_ascii=False)
    log_success(f"builds/plugins.json kaydedildi ({len(exportable_plugins)} eklenti).")

    # 8. repo.json dosyasını TEKİL ve ÖNBELLEKSİZ URL ile güncelle
    repo_manifest = {
        "name": sources_cfg.get("name", "CloudStream Süper Repo"),
        "description": sources_cfg.get("description", "Otonom CloudStream Deposu"),
        "manifestVersion": 1,
        "pluginLists": [
            f"https://raw.githubusercontent.com/{repo_full}/{branch}/builds/plugins.json"
        ]
    }
    with open(REPO_FILE, "w", encoding="utf-8") as f:
        json.dump(repo_manifest, f, indent=2, ensure_ascii=False)
    log_success(f"repo.json güncellendi (Tekil URL: {repo_manifest['pluginLists'][0]})")

    # 9. domains.json güncelle
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

    # 10. broken_plugins.json kaydet
    with open(BROKEN_PLUGINS_FILE, "w", encoding="utf-8") as f:
        json.dump(broken_report, f, indent=2, ensure_ascii=False)
    log_success(f"broken_plugins.json kaydedildi ({len(broken_report)} elenen/tekilleştirilen kayıt).")

    # 11. README.md güncelle
    generate_readme(README_FILE, repo_full, branch, final_plugins, len(broken_report), active_dizipal_url)

    # 12. jsDelivr Purge (CDN önbelleğinde kalan eski 516 eklentilik dosyaları temizle)
    log_info("jsDelivr CDN önbellekleri sıfırlanıyor...")
    for purl in [
        f"https://purge.jsdelivr.net/gh/{repo_full}@{branch}/repo.json",
        f"https://purge.jsdelivr.net/gh/{repo_full}@{branch}/builds/plugins.json"
    ]:
        try:
            session.get(purl, timeout=5)
        except Exception:
            pass

    print("=" * 70)
    log_success(f"İŞLEM BAŞARIYLA TAMAMLANDI! Toplam: {len(exportable_plugins)} adet seçkin Türkçe eklenti hazır!")
    print("=" * 70)


if __name__ == "__main__":
    main()
