# IoCManager

FortiGate ve diğer güvenlik cihazlarına tanımlanan **IP / Hash / Domain / URL
tehdit listelerini** (allowlist ve blacklist) merkezi olarak yönetmek için
geliştirilmiş, kurum içi (self-hosted) bir web portalı.

Geliştirici: DS Tech.

---

## Neden

Tehdit gösterge listeleri (IoC) genelde doğrudan sunucudaki dosya sistemi
üzerinden elle düzenlenir. Bu yöntemde:

- **Kim, ne zaman, neden** ekledi bilinmez
- Format hataları ve tekrar eden kayıtlar önlenemez
- Değişiklik geçmişi tutulmaz

IoCManager bu süreci tek bir web arayüzünde toplar: ekleme/silme işlemleri
denetlenebilir, rol bazlı yetkilendirme vardır, ve harici sistemlere
(SIEM, Cisco Umbrella, TippingPoint SMS) otomatik entegre olur.

---

## Özellikler

**Temel yönetim**
- Allowlist/Blacklist IP (CIDR destekli), Blacklist Hash (MD5/SHA1/SHA256/SHA512),
  Allowlist/Blacklist Domain (wildcard destekli), Allowlist/Blacklist URL
- Tek kutuya karışık liste yapıştır, sistem türü otomatik algılayıp doğru
  dosyaya dağıtır
- CSV/dosya ile toplu içe aktarma
- Private/özel IP aralıkları (RFC1918 vb.) otomatik engellenir

**Güvenlik**
- CSRF koruması, PBKDF2 (260.000 iterasyon) ile şifre hashleme
- Brute-force koruması ve hesap kilitleme
- Admin / Operator rol ayrımı
- Tüm işlemler audit log'a düşer (kim, ne zaman, ne, neden)

**Entegrasyonlar**
- **SIEM** — CEF formatında syslog forwarding (UDP/TCP)
- **Cisco Umbrella** — blacklist domainlerini Management API ile otomatik
  senkronize eder
- **Trend Micro TippingPoint SMS** — blacklist IP'lerini Reputation
  Database'e otomatik ekler
- **Threat Intel Sorgu** — VirusTotal, AbuseIPDB, URLScan, Shodan, MXToolbox
  ile IP/domain/URL/hash sorgulama

**İzleme**
- Servis durumu, uptime, veritabanı sağlığı, feed dosya istatistikleri
- Log görüntüleyici (crash sonrası hata araştırması için)

---

## Kurulum

İki platform desteklenir, ayrı kurulum kılavuzları mevcuttur:

| Platform | Servis yönetimi | Kılavuz |
|---|---|---|
| Windows Server | NSSM (gerçek Windows Servisi) | [`docs/KURULUM-WINDOWS.md`](docs/KURULUM-WINDOWS.md) |
| Ubuntu | systemd + gunicorn | [`docs/KURULUM-LINUX.md`](docs/KURULUM-LINUX.md) |

### Hızlı başlangıç — Windows

```powershell
git clone <bu-repo>
cd iocmanager\windows
Set-ExecutionPolicy Bypass -Scope Process -Force
.\kurulum.ps1
```

### Hızlı başlangıç — Ubuntu

```bash
git clone <bu-repo>
cd iocmanager/linux
sudo bash kurulum.sh
```

Kurulum sonrası:
```
Giriş: admin / IoCManager2026!
```
**İlk girişte şifreyi değiştirin.**

---

## Proje Yapısı

```
iocmanager/
├── app.py                   # Flask backend (platform-bagimsiz)
├── run.py                   # Waitress ile baslatici (Windows uretimde, Linux'ta manuel test)
├── requirements.txt         # Ortak bagimliliklar (flask, waitress)
├── templates/                # Web arayuzu (Jinja2)
├── static/                   # favicon vb.
├── windows/
│   └── kurulum.ps1          # Windows otomatik kurulum (NSSM tabanli)
├── linux/
│   ├── kurulum.sh           # Ubuntu otomatik kurulum (systemd tabanli)
│   ├── iocmanager.service   # systemd unit dosyasi
│   └── requirements-linux.txt
└── docs/
    ├── KURULUM-WINDOWS.md
    └── KURULUM-LINUX.md
```

Uygulama verisi (kullanıcılar, audit log, ayarlar) kuruluma göre
`data/iocmanager.db` (SQLite) dosyasında tutulur — repo'ya dahil değildir.

---

## Feed Dosyaları

FortiGate ve diğer cihazların çektiği çıktı dosyaları:

```
allowlist-ip.txt      blacklist-ip.txt      blacklist-hash.txt
allowlist-domain.txt  blacklist-domain.txt
allowlist-url.txt     blacklist-url.txt
```

Windows'ta `C:\ThreatFeed\public\`, Linux'ta `/opt/threatfeed/public/`
altında otomatik oluşturulur (ilk kayıt eklendiğinde). Konum
`IOCMANAGER_FEED_DIR` ortam değişkeni ile özelleştirilebilir.

---

## Lisans / Kullanım

Bu proje kurum içi kullanım için geliştirilmiştir.
