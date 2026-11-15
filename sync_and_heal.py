#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudStream Süper Repo: Senkronizasyon, Anti-Break ve Otonom Onarım Motoru
========================================================================
- 7 Aktif CloudStream reposundaki eklentileri (.cs3) çeker ve birleştirir.
- Akıllı çakışma yönetimi: Yüksek sürüm öncelikli, alternatifler [RepoAdı] etiketiyle saklanır.
- Anti-Break: Kaynak repo çökse veya silinse dahi yerel builds/ deposundaki sağlam dosyayı korur.
- jsDelivr CDN: Türkiye İSS/BTK raw.githubusercontent engellerini VPN gerektirmeden aşar.
- Otonom Domain & AI Onarım: domains.json içindeki adresleri test eder, 301/302 yönlendirmelerini
  yakalar ve GEMINI_API_KEY tanımlıysa erişilemeyen sitelerin yeni adreslerini Gemini ile analiz eder.
"""

import os
import sys
import json
import re
import hashlib
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# InsecureRequestWarning uyarılarını bastır
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Opsiyonel google-genai kütüphanesi kontrolü
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
README_FILE = BASE_DIR / "README.md"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
HTTP_TIMEOUT = 18
MIN_VALID_CS3_SIZE = 1024  # 1 KB altındaki dosyalar bozuk/hata sayfası kabul edilir
MAX_WORKERS = 12           # Eşzamanlı indirme ve kontrol iş parçacığı sayısı


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


def log_domain(msg: str) -> None:
    print(f"\033[96m[DOMAİN]\033[0m {msg}", flush=True)


def log_ai(msg: str) -> None:
    print(f"\033[35m[AI ONARIM]\033[0m {msg}", flush=True)


# =====================================================================
# YARDIMCI FONKSİYONLAR
# =====================================================================
def get_session(pool_size: int = 25) -> requests.Session:
    """Tekrar kullanılabilir, bağlantı havuzlu ve User-Agent tanımlı istek oturumu üretir."""
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
    """Dosyanın SHA-256 özetini sha256-<hex> formatında hesaplar."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return f"sha256-{hasher.hexdigest()}"


def sanitize_filename(name: str) -> str:
    """Dosya adı için güvenli karakter dizisi oluşturur."""
    cleaned = re.sub(r'[^\w\-_\.]', '_', name)
    cleaned = re.sub(r'_+', '_', cleaned).strip('_')
    return cleaned or "plugin"


def sanitize_repo_slug(name: str) -> str:
    """Repo adına göre kısa ve temiz tanımlayıcı oluşturur."""
    cleaned = re.sub(r'[^a-zA-Z0-9]', '', name)
    return cleaned or "Repo"


def get_repo_identifier(sources_cfg: Dict[str, Any]) -> Tuple[str, str]:
    """
    GitHub Actions ortamında github.repository değişkenini okur;
    yerel ortamda ise sources.json içindeki varsayılan alanları kullanır.
    """
    env_repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    branch = sources_cfg.get("branch", "main").strip()

    if env_repo and "/" in env_repo:
        return env_repo, branch

    user = sources_cfg.get("default_github_user", "MrKonce")
    repo = sources_cfg.get("default_github_repo", "ozel-cs-repom")
    return f"{user}/{repo}", branch


def convert_to_cdn_url(repo_full: str, branch: str, filename: str) -> str:
    """Eklenti dosyasını doğrudan jsDelivr CDN indirme linkine çevirir."""
    return f"https://cdn.jsdelivr.net/gh/{repo_full}@{branch}/builds/{filename}"


def convert_github_raw_to_cdn(raw_url: Optional[str]) -> Optional[str]:
    """
    Eğer ikon veya kaynak URL raw.githubusercontent.com üzerindeyse,
    Türkiye'deki erişim engellerine takılmaması için jsDelivr CDN'e dönüştürür.
    """
    if not raw_url or not isinstance(raw_url, str):
        return raw_url

    raw_pattern = r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$"
    match = re.match(raw_pattern, raw_url)
    if match:
        owner, repo, branch_or_commit, path = match.groups()
        return f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch_or_commit}/{path}"

    return raw_url


# =====================================================================
# ADIM 1: KAYNAKLARDAN EKLENTİLERİ ÇEKME
# =====================================================================
def fetch_source_plugins(session: requests.Session, source: Dict[str, Any], blacklist: List[str]) -> Tuple[List[Dict[str, Any]], bool]:
    """
    Tek bir kaynağın repo.json dosyasını ve oradaki pluginLists listelerini çeker.
    """
    name = source.get("name", "Bilinmeyen")
    url = source.get("url", "")
    priority = source.get("priority", 99)
    plugins_found: List[Dict[str, Any]] = []

    if not url:
        return plugins_found, False

    log_info(f"[{name}] Taranıyor (Öncelik: {priority}) -> {url}")
    try:
        resp = session.get(url, timeout=HTTP_TIMEOUT)
        if resp.status_code != 200:
            log_warn(f"[{name}] repo.json alınamadı (HTTP {resp.status_code})")
            return plugins_found, False

        repo_data = resp.json()
        plugin_lists = repo_data.get("pluginLists", [])

        if not plugin_lists and isinstance(repo_data, list):
            plugin_lists = [url]

        for p_list_url in plugin_lists:
            try:
                p_resp = session.get(p_list_url, timeout=HTTP_TIMEOUT)
                if p_resp.status_code != 200:
                    log_warn(f"[{name}] Eklenti listesi indirilemedi: {p_list_url} (HTTP {p_resp.status_code})")
                    continue

                p_data = p_resp.json()
                items: List[Dict[str, Any]] = []
                if isinstance(p_data, list):
                    items = p_data
                elif isinstance(p_data, dict):
                    items = list(p_data.values())

                for item in items:
                    if not isinstance(item, dict):
                        continue
                    in_name = item.get("internalName") or item.get("name")
                    item_name = item.get("name", "")

                    # Kara liste kontrolü
                    if in_name in blacklist or item_name in blacklist:
                        log_info(f"[{name}] Kara listede olduğu için atlandı: {item_name}")
                        continue

                    # Meta bilgileri ekle
                    enriched_item = dict(item)
                    enriched_item["_source_name"] = name
                    enriched_item["_source_priority"] = priority
                    enriched_item["_source_url"] = url
                    plugins_found.append(enriched_item)

            except Exception as e:
                log_warn(f"[{name}] Liste ayrıştırma hatası ({p_list_url}): {e}")

        log_success(f"[{name}] {len(plugins_found)} eklenti keşfedildi.")
        return plugins_found, True

    except Exception as e:
        log_error(f"[{name}] Kaynak tarama hatası: {e}")
        return plugins_found, False


# =====================================================================
# ADIM 2: ÇAKIŞMA YÖNETİMİ & ALTERNATİF SÜRÜM ÇÖZÜMLEME
# =====================================================================
def resolve_plugin_conflicts(all_plugins: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Aynı internalName değerine sahip eklentileri analiz eder:
    - En yüksek version numarasına ve önceliğe sahip olanı 'ana eklenti' seçer.
    - Farklı repolardan gelen alternatifleri [KaynakRepoAdı] etiketiyle
      çakışmayacak benzersiz internalName ve dosya adıyla ayrı bir eklenti olarak kaydeder.
    """
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for p in all_plugins:
        key = p.get("internalName") or p.get("name") or "unknown"
        grouped.setdefault(key, []).append(p)

    final_candidates: List[Dict[str, Any]] = []

    for key, items in grouped.items():
        if len(items) == 1:
            item = dict(items[0])
            item["_is_alternative"] = False
            final_candidates.append(item)
            continue

        # Çoklu eklenti: version (büyük olan) ve _source_priority (küçük olan öncelikli) sırala
        sorted_items = sorted(
            items,
            key=lambda x: (int(x.get("version", 0) or 0), -int(x.get("_source_priority", 99))),
            reverse=True
        )

        # 1. Ana eklenti (En yüksek sürüm ve öncelik)
        main_item = dict(sorted_items[0])
        main_item["_is_alternative"] = False
        final_candidates.append(main_item)

        # 2. Alternatif eklentiler (Diğer repolardan gelen sağlam alternatifler)
        seen_repos = {main_item["_source_name"]}
        for alt_item in sorted_items[1:]:
            repo_name = alt_item["_source_name"]
            if repo_name in seen_repos:
                continue
            seen_repos.add(repo_name)

            slug = sanitize_repo_slug(repo_name)
            alt = dict(alt_item)
            alt["_is_alternative"] = True
            alt["_alt_slug"] = slug

            # CloudStream'de çakışmaması ve ayrı görünebilmesi için ad ve internalName güncelle
            orig_name = alt.get("name", key)
            alt["name"] = f"{orig_name} [{repo_name}]"
            alt["internalName"] = f"{key}_{slug}"
            alt["description"] = f"[{repo_name} Alternatifi] " + alt.get("description", "")
            final_candidates.append(alt)

    return final_candidates


# =====================================================================
# ADIM 3: ANTI-BREAK & CS3 İNDİRME / SAĞLIK KONTROLÜ
# =====================================================================
def download_and_heal_cs3(
    session: requests.Session,
    candidate: Dict[str, Any],
    builds_dir: Path,
    previous_plugins_map: Dict[str, Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """
    .cs3 dosyasını kontrol eder:
    - HTTP 200 dönüyor mu ve dosya boyutu > 1024 byte mı?
    - Sağlamsa builds/ klasörüne indirir ve doğrular.
    - Eğer kaynak bozulmuş/kapanmışsa, yereldeki eski sağlam dosyayı korur (Anti-Break).
    """
    raw_name = candidate.get("internalName") or candidate.get("name") or "plugin"
    base_filename = sanitize_filename(candidate.get("internalName", raw_name))
    target_filename = f"{base_filename}.cs3"
    target_path = builds_dir / target_filename
    remote_url = candidate.get("url", "")
    download_success = False

    # 1. Uzak URL'den indirmeyi dene
    if remote_url:
        try:
            resp = session.get(remote_url, timeout=HTTP_TIMEOUT, stream=True)
            if resp.status_code == 200:
                content = resp.content
                if len(content) >= MIN_VALID_CS3_SIZE:
                    with open(target_path, "wb") as f:
                        f.write(content)
                    download_success = True
                else:
                    log_warn(f"[{candidate.get('name')}] İndirilen dosya boyutu yetersiz ({len(content)} B).")
            else:
                log_warn(f"[{candidate.get('name')}] İndirme bağlantısı geçersiz (HTTP {resp.status_code}): {remote_url}")
        except Exception as e:
            log_warn(f"[{candidate.get('name')}] İndirme hatası ({remote_url}): {e}")

    # 2. Eğer indirme başarısız olduysa Anti-Break devreye girer
    if not download_success:
        if target_path.exists() and target_path.stat().st_size >= MIN_VALID_CS3_SIZE:
            log_anti_break(
                f"KAYNAK KORUNDU: '{candidate.get('name')}' için uzaktaki link kırık fakat "
                f"mevcut yerel dosya ({target_path.stat().st_size} B) kurtarıldı!"
            )
            download_success = True
        else:
            prev_entry = previous_plugins_map.get(candidate.get("internalName", ""))
            if prev_entry:
                prev_file = builds_dir / f"{sanitize_filename(prev_entry.get('internalName', ''))}.cs3"
                if prev_file.exists() and prev_file.stat().st_size >= MIN_VALID_CS3_SIZE:
                    log_anti_break(f"GEÇMİŞTEN KURTARILDI: '{candidate.get('name')}' önceki sürümden korundu.")
                    target_path = prev_file
                    target_filename = prev_file.name
                    download_success = True

    if not download_success:
        log_error(f"Eklenti kullanılamıyor, atlandı: {candidate.get('name')}")
        return None

    # Dosya boyutunu ve SHA-256 özetini güncelle
    actual_size = target_path.stat().st_size
    actual_hash = compute_sha256(target_path)

    verified_plugin = dict(candidate)
    verified_plugin["fileSize"] = actual_size
    verified_plugin["fileHash"] = actual_hash
    verified_plugin["_local_filename"] = target_filename

    # İkon URL'sini jsDelivr formatına çevir (ISS engeli yememesi için)
    if "iconUrl" in verified_plugin:
        verified_plugin["iconUrl"] = convert_github_raw_to_cdn(verified_plugin["iconUrl"])

    return verified_plugin


# =====================================================================
# ADIM 4: OTONOM DOMAİN & GEMINI AI ONARIM MODÜLÜ
# =====================================================================
def run_autonomous_domain_and_ai_heal(
    session: requests.Session,
    domain_source_url: str,
    domains_file: Path
) -> Dict[str, List[str]]:
    """
    - TurkSinema domains.json dosyasını çeker ve yerel domains.json ile harmanlar.
    - 301/302 HTTP yönlendirmelerini takip ederek değişen domainleri günceller.
    - GEMINI_API_KEY ortam değişkeni varsa, ulaşılamayan siteler için Gemini 2.5 Flash ile analiz yapar.
    """
    log_domain("Otonom Domain & AI Onarım Modülü başlatılıyor...")

    domains_data: Dict[str, List[str]] = {}
    if domains_file.exists():
        try:
            with open(domains_file, "r", encoding="utf-8") as f:
                domains_data = json.load(f)
        except Exception as e:
            log_warn(f"Mevcut domains.json okunamadı: {e}")

    # Uzak domains.json'ı çek
    if domain_source_url:
        try:
            resp = session.get(domain_source_url, timeout=HTTP_TIMEOUT)
            if resp.status_code == 200:
                remote_domains = resp.json()
                for site_name, url_list in remote_domains.items():
                    if isinstance(url_list, list):
                        existing = domains_data.setdefault(site_name, [])
                        for u in url_list:
                            if u not in existing:
                                existing.append(u)
                log_success(f"Uzak domain listesi başarıyla alındı ({len(remote_domains)} site).")
        except Exception as e:
            log_warn(f"Uzak domain listesi alınamadı: {e}")

    if not domains_data:
        log_warn("Kontrol edilecek domain verisi bulunamadı.")
        return domains_data

    # Gemini API İstemcisi Hazırlığı (Opsiyonel)
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    ai_client = None
    if gemini_key:
        if GENAI_AVAILABLE:
            try:
                ai_client = genai.Client(api_key=gemini_key)
                log_ai("Gemini API (gemini-2.5-flash) istemcisi aktif.")
            except Exception as e:
                log_warn(f"Gemini istemcisi başlatılamadı: {e}")
        else:
            log_warn("google-genai kütüphanesi kurulu değil, AI onarım atlanıyor.")
    else:
        log_info("GEMINI_API_KEY tanımlı değil; AI analizi atlanıyor (opsiyonel).")

    healed_domains: Dict[str, List[str]] = {}

    for site_name, urls in domains_data.items():
        if not isinstance(urls, list):
            urls = [str(urls)]

        active_urls: List[str] = []
        site_working = False

        for url in urls:
            clean_url = url.strip()
            if not clean_url:
                continue

            try:
                r = session.get(clean_url, timeout=8, allow_redirects=True)
                final_url = r.url

                parsed_orig = urllib.parse.urlparse(clean_url)
                parsed_final = urllib.parse.urlparse(final_url)

                orig_base = f"{parsed_orig.scheme}://{parsed_orig.netloc}"
                final_base = f"{parsed_final.scheme}://{parsed_final.netloc}"

                if r.status_code in [200, 301, 302, 307, 308]:
                    site_working = True
                    if orig_base.lower() != final_base.lower():
                        log_domain(f"[{site_name}] Yönlendirme tespit edildi: {clean_url} -> {final_base}")
                        if final_base not in active_urls:
                            active_urls.insert(0, final_base)
                    
                    if clean_url not in active_urls:
                        active_urls.append(clean_url)
                else:
                    log_warn(f"[{site_name}] {clean_url} durum kodu: {r.status_code}")
                    if clean_url not in active_urls:
                        active_urls.append(clean_url)
            except Exception as e:
                log_warn(f"[{site_name}] Bağlantı kurulamadı ({clean_url}): {e}")
                if clean_url not in active_urls:
                    active_urls.append(clean_url)

        # Tüm adresler kapalıysa ve Gemini aktifse yapay zeka ile tahmin yürüt
        if not site_working and ai_client:
            log_ai(f"[{site_name}] Tüm adresler kapalı. Gemini 2.5 Flash ile alternatif taranıyor...")
            try:
                prompt = (
                    f"Sen bir web scraping ve streaming sitesi alan adı uzmanısın.\n"
                    f"Türkiye'de yayın yapan '{site_name}' isimli dizi/film sitesinin şu anki alan adları çalışmıyor.\n"
                    f"Eski adresler: {urls}\n"
                    f"Bu sitenin güncel ayna (mirror), yedek veya yeni taşındığı alan adını biliyorsan veya tahmin "
                    f"edebiliyorsan yalnızca JSON formatında bir dizi olarak döndür.\n"
                    f"Örnek çıktı formatı: [\"https://yeniadres.org\"]\n"
                    f"Sadece ve sadece JSON formatında yanıt ver, başka hiçbir açıklama yazma."
                )
                response = ai_client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt
                )
                raw_text = response.text.strip()
                match = re.search(r'\[.*?\]', raw_text, re.DOTALL)
                if match:
                    suggested = json.loads(match.group(0))
                    for sug_url in suggested:
                        if isinstance(sug_url, str) and sug_url.startswith("http"):
                            try:
                                chk = session.get(sug_url, timeout=6)
                                if chk.status_code == 200:
                                    log_ai(f"[{site_name}] Gemini'ın önerdiği adres doğrulandı: {sug_url}")
                                    active_urls.insert(0, sug_url)
                                else:
                                    active_urls.append(sug_url)
                            except Exception:
                                active_urls.append(sug_url)
            except Exception as e:
                log_warn(f"[{site_name}] Gemini analizi tamamlanamadı: {e}")

        healed_domains[site_name] = active_urls

    with open(domains_file, "w", encoding="utf-8") as f:
        json.dump(healed_domains, f, indent=2, ensure_ascii=False)
    log_success(f"Güncel domains.json kaydedildi ({len(healed_domains)} site).")

    return healed_domains


# =====================================================================
# ADIM 5: README.MD OLUŞTURUCU
# =====================================================================
def generate_readme(
    readme_path: Path,
    repo_full: str,
    branch: str,
    total_plugins: int,
    source_stats: List[Dict[str, Any]],
    final_plugins: List[Dict[str, Any]],
    healed_domains_count: int
) -> None:
    """
    README.md dosyasını şık, bilgilendirici ve profesyonel bir yapıda otomatik üretir.
    """
    now_utc = datetime.now(timezone.utc)
    now_tr = now_utc + timedelta(hours=3)
    formatted_time = now_tr.strftime("%d.%m.%Y - %H:%M:%S (TSİ / GMT+3)")

    super_repo_url = f"https://cdn.jsdelivr.net/gh/{repo_full}@{branch}/repo.json"

    lines = [
        "# ⚡ CloudStream Süper Repo (Otonom & Anti-Break & jsDelivr)",
        "",
        "> **En güncel Türkçe ve Global CloudStream eklentilerini (.cs3) tek bir adreste toplayan,**",
        "> **Anti-Break teknolojisiyle silinen repoları dahi koruyan ve Türkiye İSS/BTK engellerine takılmayan otonom süper repo.**",
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
        f"- 📦 **Toplam Sağlam Eklenti:** `{total_plugins}` adet",
        f"- 🌐 **İzlenen / Onarılan Film-Dizi Sitesi:** `{healed_domains_count}` adet",
        f"- 🛡️ **Anti-Break Koruması:** `Aktif (Yerel Öncelikli Yedekleme)`",
        f"- ⚡ **CDN Hızlandırma:** `jsDelivr Global Edge Network`",
        "",
        "### 📚 Kaynak Repo Durumları",
        "",
        "| Öncelik | Kaynak Repo | Dil | Durum | Çekilen Sağlam Eklenti |",
        "|:---:|:---|:---:|:---:|:---:|",
    ]

    for stat in source_stats:
        status_badge = "🟢 Aktif" if stat["active"] else "🔴 Ulaşılamadı (Anti-Break devrede)"
        lines.append(
            f"| **{stat['priority']}** | [{stat['name']}]({stat['url']}) | `{stat['language']}` | "
            f"{status_badge} | **{stat['count']}** |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 🌟 Temel Özellikler",
        "",
        "1. **🛡️ Anti-Break (Kesintisiz Çalışma Garantisi):**",
        "   Kaynak repolardan biri GitHub tarafından kapatılsa, silinse veya linkleri kırılsa bile,",
        "   yerel depomuzdaki çalışan en son sağlam `.cs3` dosyası asla silinmez ve kullanıcılara sunulmaya devam eder.",
        "",
        "2. **🇹🇷 Türkiye İSS & BTK Engellerini Aşma (jsDelivr CDN):**",
        "   Tüm `.cs3` indirme linkleri ve `plugins.json` listesi `cdn.jsdelivr.net` ağına dönüştürülür.",
        "   Böylece `raw.githubusercontent.com` engelleri aşılır; Turkcell, Vodafone, Türk Telekom gibi sağlayıcılarda",
        "   VPN açmaya gerek kalmadan yüksek hızda indirme yapılır.",
        "",
        "3. **🔄 Akıllı Sürüm & Çakışma Yönetimi:**",
        "   Aynı eklenti birden fazla repoda bulunuyorsa en yüksek `version` numaralı olan birincil eklenti seçilir.",
        "   Diğer repodaki alternatif de sağlamsa, `[RepoAdı]` etiketiyle (örn. `HDFilmcehennemi [BTVault]`)",
        "   ayrı bir eklenti olarak sunulur; böylece biri bozulsa diğeri hemen kullanılabilir.",
        "",
        "4. **🌐 Otonom Domain & AI Onarım:**",
        "   Film/dizi sitelerinin adres değişiklikleri (301/302) otomatik izlenir.",
        "   Kapanan siteler için Gemini 2.5 Flash yapay zekası devreye girerek yeni alan adı önerilerini analiz eder.",
        "",
        "---",
        "",
        "## 📦 Bulunan Eklentiler Listesi",
        "",
        f"<details><summary><b>Toplam {len(final_plugins)} Eklentiyi Görmek İçin Tıklayın</b></summary>",
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
        "## ⚙️ Otomatik Güncelleme",
        "",
        "Bu repo GitHub Actions ile **her 6 saatte bir** (`0 */6 * * *`) otomatik olarak güncellenir,",
        "yeni eklentiler taranır, domainler onarılır ve jsDelivr önbelleği otomatik olarak temizlenir (Purge).",
        "",
        "_Otomatik olarak oluşturulmuştur. El ile düzenlemeyiniz._"
    ])

    with open(readme_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log_success("README.md dosyası oluşturuldu.")


# =====================================================================
# ANA ÇALIŞMA FONKSİYONU
# =====================================================================
def main() -> None:
    print("=" * 70)
    print("   CLOUDSTREAM SÜPER REPO: SENKRONİZASYON VE ONARIM MOTORU   ")
    print("=" * 70)

    # 1. Klasör hazırlığı
    BUILDS_DIR.mkdir(parents=True, exist_ok=True)

    # 2. sources.json yükle
    if not SOURCES_FILE.exists():
        log_error(f"sources.json dosyası bulunamadı: {SOURCES_FILE}")
        sys.exit(1)

    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources_cfg = json.load(f)

    repo_full, branch = get_repo_identifier(sources_cfg)
    log_info(f"Hedef GitHub Deposu: {repo_full} (Dal: {branch})")

    sources_list = sources_cfg.get("sources", [])
    blacklist = sources_cfg.get("blacklist", [])
    domain_source_url = sources_cfg.get("domain_source_url", "")

    # Kaynakları öncelik sırasına göre sırala (Öncelik 1 en üstte)
    sources_list = sorted(sources_list, key=lambda x: x.get("priority", 99))

    # 3. Önceki plugins.json verisini oku (Anti-Break için referans)
    previous_plugins_map: Dict[str, Dict[str, Any]] = {}
    if PLUGINS_FILE.exists():
        try:
            with open(PLUGINS_FILE, "r", encoding="utf-8") as f:
                prev_data = json.load(f)
                items = prev_data if isinstance(prev_data, list) else list(prev_data.values())
                for item in items:
                    in_n = item.get("internalName")
                    if in_n:
                        previous_plugins_map[in_n] = item
            log_info(f"Önceki senkronizasyondan {len(previous_plugins_map)} eklenti belleğe alındı.")
        except Exception as e:
            log_warn(f"Eski plugins.json okunamadı: {e}")

    session = get_session(pool_size=MAX_WORKERS * 2)

    # 4. Tüm kaynakları tara ve eklentileri topla
    raw_collected_plugins: List[Dict[str, Any]] = []
    source_stats: List[Dict[str, Any]] = []

    for src in sources_list:
        if not src.get("enabled", True):
            continue
        p_list, is_active = fetch_source_plugins(session, src, blacklist)
        raw_collected_plugins.extend(p_list)
        source_stats.append({
            "name": src.get("name"),
            "url": src.get("url"),
            "priority": src.get("priority"),
            "language": src.get("language", "tr"),
            "active": is_active,
            "count": len(p_list)
        })

    log_info(f"Toplam toplanan ham eklenti kaydı: {len(raw_collected_plugins)}")

    # 5. Çakışma yönetimi ve alternatif çözümleme
    candidate_plugins = resolve_plugin_conflicts(raw_collected_plugins)
    log_info(f"Çözümlenmiş aday eklenti sayısı: {len(candidate_plugins)}")

    # 6. Anti-Break & Eşzamanlı CS3 indirme / doğrulama
    log_info(f"Eklentiler indiriliyor ve Anti-Break doğrulaması yapılıyor ({MAX_WORKERS} iş parçacığı)...")
    final_plugins: List[Dict[str, Any]] = []
    processed_internal_names = set()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_candidate = {
            executor.submit(download_and_heal_cs3, session, candidate, BUILDS_DIR, previous_plugins_map): candidate
            for candidate in candidate_plugins
        }
        for future in as_completed(future_to_candidate):
            verified = future.result()
            if verified:
                local_filename = verified["_local_filename"]
                verified["url"] = convert_to_cdn_url(repo_full, branch, local_filename)

                clean_item = {k: v for k, v in verified.items() if not k.startswith("_")}
                clean_item["_source_name"] = verified.get("_source_name", "Bilinmeyen")

                final_plugins.append(clean_item)
                processed_internal_names.add(verified.get("internalName"))

    # 7. Derin Anti-Break: Önceki plugins.json içinde olup bugün kaynak repoda
    # bulunamayan AMA yerel diskte sağlam olan eklentileri de koru!
    for in_name, prev_item in previous_plugins_map.items():
        if in_name not in processed_internal_names and in_name not in blacklist:
            base_fname = sanitize_filename(in_name)
            candidate_file = BUILDS_DIR / f"{base_fname}.cs3"
            if candidate_file.exists() and candidate_file.stat().st_size >= MIN_VALID_CS3_SIZE:
                log_anti_break(f"DERİN ANTI-BREAK KORUMASI: Kaynakta silinmiş olan '{in_name}' yerelden kurtarıldı.")
                restored_item = dict(prev_item)
                restored_item["url"] = convert_to_cdn_url(repo_full, branch, candidate_file.name)
                restored_item["fileSize"] = candidate_file.stat().st_size
                restored_item["fileHash"] = compute_sha256(candidate_file)
                restored_item["_source_name"] = prev_item.get("_source_name", "Önceki Yedek (Anti-Break)")
                final_plugins.append(restored_item)
                processed_internal_names.add(in_name)

    log_success(f"Nihai sağlam eklenti sayısı: {len(final_plugins)}")

    # 8. builds/plugins.json dosyasını kaydet
    exportable_plugins = []
    for p in final_plugins:
        clean_dict = {k: v for k, v in p.items() if not k.startswith("_")}
        exportable_plugins.append(clean_dict)

    with open(PLUGINS_FILE, "w", encoding="utf-8") as f:
        json.dump(exportable_plugins, f, indent=2, ensure_ascii=False)
    log_success(f"builds/plugins.json oluşturuldu ({len(exportable_plugins)} eklenti).")

    # 9. Ana dizindeki repo.json dosyasını güncelle
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

    # 10. Otonom Domain & AI Onarım modülünü çalıştır
    healed_domains = run_autonomous_domain_and_ai_heal(session, domain_source_url, DOMAINS_FILE)

    # 11. README.md dosyasını güncelle
    generate_readme(
        README_FILE,
        repo_full,
        branch,
        len(final_plugins),
        source_stats,
        final_plugins,
        len(healed_domains)
    )

    print("=" * 70)
    log_success("Tüm işlemler başarıyla tamamlandı!")
    print("=" * 70)


if __name__ == "__main__":
    main()
