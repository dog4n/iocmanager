# IoCManager v1.6.10 — Windows Kurulum Kılavuzu

Windows Server icin, GPO kisitlamalarina uyumlu (sisteme Python kurulumu yapmaz).
Servis yonetimi **NSSM** ile gercek bir Windows Servisi olarak yapilir — Task
Scheduler kullanilmaz (oturum/RDP durumundan etkilenip sessizce durabiliyordu).

---

## Hizli Kurulum (3 adim)

**1.** Bu repo'yu (`git clone` ile veya ZIP indirerek) sunucuya kopyala

**2.** PowerShell'i **Yonetici olarak** ac

**3.** Klasore girip kurulumu baslat:
```powershell
cd "C:\Users\<kullanici>\Downloads\iocmanager\windows"
Set-ExecutionPolicy Bypass -Scope Process -Force
.\kurulum.ps1
```

Script otomatik olarak:
- `C:\IoCManager` uygulama klasorunu olusturur
- `C:\ThreatFeed\public` feed klasorunu olusturur
- Embeddable Python indirir (GPO uyumlu, **sisteme kurulum yapmaz**, sadece klasore cikartir)
- pip, Flask, Waitress kurar
- Firewall kurali ekler (port 5000)
- **NSSM indirir** ve `IoCManager` adinda gercek bir Windows Servisi kurar
- Servisi `Automatic` baslangic tipiyle baslatir

---

## Neden NSSM (Task Scheduler degil)?

Onceki surumlerde Task Scheduler kullaniliyordu, ancak zamanla gorev sessizce
`Ready` durumuna donup servis erisilemez hale geliyordu — bu da LB tarafinda
"down" olarak goruluyordu. NSSM gercek bir Windows Servisi olusturur:

- **Oturum/RDP durumundan bagimsiz** calisir
- Process herhangi bir nedenle kaparsa **5 saniyede otomatik yeniden baslar**
  (`AppExit Default Restart`)
- `services.msc` / `Get-Service` ile standart sekilde izlenir
- Reboot'ta `Automatic` baslangic tipiyle kendiliginden acilir

---

## Kurulum Sonrasi

```
Portal : http://SUNUCU_ADI:5000
Giris  : admin / IoCManager2026!
```

**Ilk giriste sifreyi degistir** — nav menusunden "Sifre Degistir".

---

## Sistem Izleme Ekrani

**Izleme** sekmesi (sadece admin) uygulamanin kendi icinden servis sagligini
gosterir:

- **Servis durumu** — `sc query IoCManager` ile canli sorgulanir
- **Uptime** — bu worker'in ne zamandir ayakta oldugu (servis yeniden
  baslarsa sifirlanir, bu yuzden beklenmedik bir restart oldugunda uptime'in
  sifirlandigini gorursun)
- **Veritabani** erisim durumu ve boyutu
- **Feed dosyalari** — her birinin kayit sayisi, boyutu, son guncelleme zamani
- **Son 24 saat aktivite** — ekleme/silme/giris/basarisiz giris sayilari
- **Log Goruntuleyici** — `service-out.log`, `service-err.log` ve
  `iocmanager-cef.log` dosyalarinin son N satirini (100-1000 arasi secilebilir)
  dogrudan tarayicidan gosterir; PowerShell'e gecmeden gecmise donuk hata
  arastirmasi yapabilirsin

Bu ekran, NSSM'in crash loglarini (`service-err.log`) PowerShell'e girmeden
tarayicidan takip etmeni saglar.

---

## Dizin Yapisi

```
C:\IoCManager\
├── app.py
├── run.py
├── python\                    ← Embeddable Python (kurulum degil, sadece klasor)
├── nssm\                       ← NSSM servis araci
├── templates\
├── static\
├── data\
│   └── iocmanager.db          ← kullanicilar, audit log, ayarlar, API anahtarlari
└── logs\
    ├── iocmanager-cef.log     ← SIEM CEF logu
    ├── service-out.log        ← servis stdout (NSSM)
    └── service-err.log        ← servis stderr / crash loglari (NSSM)

C:\ThreatFeed\public\          ← FortiGate/Umbrella'nin cektigi feed dosyalari
├── allowlist-ip.txt
├── blacklist-ip.txt
├── blacklist-hash.txt
├── allowlist-domain.txt
├── blacklist-domain.txt
├── allowlist-url.txt
└── blacklist-url.txt
```

Feed dosyalari ilk kayit eklendiginde otomatik olusur.

---

## Servis Yonetimi

```powershell
Get-Service IoCManager | Select Name, StartType, Status
Start-Service   IoCManager
Stop-Service    IoCManager
Restart-Service IoCManager
```

Servis `Automatic` baslangic tipiyle, SYSTEM hesabi altinda calisir — RDP
oturumu kapansa da, kullanici logout olsa da, sunucu reboot olsa da calismaya
devam eder / kendiliginden baslar.

Crash loglarini gormek icin:
```powershell
Get-Content C:\IoCManager\logs\service-err.log -Tail 50
Get-Content C:\IoCManager\logs\service-out.log -Tail 50
```

---

## Guncelleme (kod degisince)

Kullanicilari ve gecmis kayitlari koruyarak sadece uygulama kodunu guncelle.
Komutlari **repo kokunden** (windows/ klasorunun bir ustunden) calistir:

```powershell
cd ..   # windows/ klasorundeysen repo kokune cik
Stop-Service IoCManager

Copy-Item ".\app.py" C:\IoCManager\app.py -Force
Copy-Item ".\templates\*" C:\IoCManager\templates\ -Recurse -Force

Start-Service IoCManager
Start-Sleep -Seconds 3
Get-Service IoCManager | Select Status
```

`data\` (veritabani), `python\` (Python kurulumu) ve `nssm\` klasorlerine
**dokunma** — bunlar guncellemeler arasi korunmali.

> **Onemli:** Guncelleme sonrasi tarayicida degisiklikler gorunmuyorsa
> **Ctrl+Shift+R** ile sert yenileme yap — tarayici eski sayfayi cache'lemis
> olabilir.

---

## Manuel Test / Sorun Giderme

Servis baslamiyorsa elle calistirip hatayi gormek icin:

```powershell
Stop-Service IoCManager
C:\IoCManager\python\python.exe C:\IoCManager\run.py
```

Hata mesaji terminalde gorunur. `Ctrl+C` ile durdur, sonra:
```powershell
Start-Service IoCManager
```

Servis hic kurulmamis / silinmis gibi davraniyorsa, NSSM ile yeniden kaydet:
```powershell
$nssm = "C:\IoCManager\nssm\nssm-2.24\win64\nssm.exe"
& $nssm install IoCManager "C:\IoCManager\python\python.exe" "C:\IoCManager\run.py"
& $nssm set IoCManager AppDirectory "C:\IoCManager"
& $nssm set IoCManager AppExit Default Restart
& $nssm set IoCManager AppRestartDelay 5000
Set-Service IoCManager -StartupType Automatic
Start-Service IoCManager
```

---

## LB / Firewall Kontrol Listesi

Dis erisim sorunlarinda sirasiyla kontrol et:

```powershell
# 1. Servis calisiyor mu
Get-Service IoCManager | Select Status

# 2. Sunucudan yerel erisim
Invoke-WebRequest http://localhost:5000 -UseBasicParsing | Select StatusCode

# 3. Port dogru arayuzde dinliyor mu (0.0.0.0 olmali, 127.0.0.1 degil)
netstat -ano | findstr :5000

# 4. Firewall kurali acik mi
Get-NetFirewallRule -DisplayName "IoCManager" | Select Enabled, Direction, Action
```

LB health check kullaniyorsan, kontrol ettigi path'in `/` (login sayfasi,
200 doner) oldugundan emin ol — `/dashboard` gibi login gerektiren bir path'e
bakiyorsa 302 alir ve "unhealthy" sayabilir.

---

## Threat Intel API (Sorgu sekmesi)

**Entegrasyonlar** sayfasi → Threat Intel API Anahtarlari karti uzerinden
VirusTotal, AbuseIPDB, URLScan, Shodan, MXToolbox anahtarlarini girebilirsiniz.
Anahtar girilen kaynaklar **Sorgu** sekmesinde (tum kullanicilara acik) aktif
olur; bos birakilan kaynaklar sessizce atlanir.

Sorgu sayfasinda IP/domain/URL/hash girip tek seferde tum aktif kaynaklardan
sonuc alabilirsiniz — zararli skoru, reputation, kategori, ilgili IP/domain
listesi gibi bilgiler dahildir. URLScan icin ekran goruntusu **gosterilmez**,
sadece metinsel sonuclar sunulur.

---

## Cisco Umbrella Entegrasyonu (opsiyonel)

`blacklist-domain` listesindeki domainleri Umbrella'da otomatik olusturulan
**"IoCManager Blacklist"** destination list'ine (block tipi) yazar.

**Entegrasyonlar** sayfasi → Cisco Umbrella Entegrasyonu karti:
1. **Aktif** kutusunu isaretle
2. **Management API Key** ve **Management API Secret** gir
   (Umbrella Dashboard → Admin → API Keys → Management API'den alinir)
3. **Otomatik Sync** isaretle (her ekleme/silme aninda Umbrella'ya yansisin diye)
4. Kaydet, sonra **Baglanti Testi** ile dogrula
5. Mevcut kayitlari toplu gondermek icin **Umbrella'ya Senkronize Et**

> Umbrella listeyi olusturdugunda, o listeyi bir **policy'ye baglamak**
> Umbrella Dashboard tarafinda ayri bir adimdir — IoCManager sadece domaini
> listeye yazar, hangi policy'nin bu listeyi block edecegini Umbrella'da
> ayarlarsin (Policies → Management → ilgili policy → Destination Lists).

### "SSL: CERTIFICATE_VERIFY_FAILED / self-signed certificate" hatasi

Kurumsal agda genelde bir **SSL inceleme cihazi** (Zscaler, Fortinet, Palo
Alto vb.) tum HTTPS trafigini acip kendi sertifikasiyla yeniden imzalar.
Embeddable Python bu kurumsal sertifikayi tanimadigi icin baglanti
reddedilir. Cozum, kurumsal kok sertifikayi Python'a tanitmak:

1. **Kok sertifikayi al** — Chrome'da `https://api.umbrella.com` adresine
   git, adres cubugundaki kilide tikla → sertifika zincirinin en ustundeki
   (root) sertifikayi **Base-64 encoded X.509 (.CER)** olarak export et.
   Ya da IT'den `.pem`/`.crt` dosyasini iste.

2. **Sunucuya kopyala:**
   ```powershell
   Copy-Item "C:\indirilen\kurumsal-ca.crt" C:\IoCManager\corp-ca.pem
   ```

3. **Servise ortam degiskeni olarak tanit** (NSSM):
   ```powershell
   $nssm = "C:\IoCManager\nssm\nssm-2.24\win64\nssm.exe"
   & $nssm set IoCManager AppEnvironmentExtra "IOCMANAGER_CA_BUNDLE=C:\IoCManager\corp-ca.pem"
   Restart-Service IoCManager
   ```

4. **Tekrar test et** — Entegrasyonlar sayfasinda Umbrella **Baglanti Testi**.

Sertifika verilmezse uygulama sistemin varsayilan sertifika deposunu
kullanmaya devam eder, mevcut davranis degismez. **IOCMANAGER_CA_BUNDLE**
verildiginde sertifika sistemin varsayilan guven deposuna **eklenir**,
yerine gecmez — yani ozel/kurumsal sertifika tanimlamak VirusTotal,
AbuseIPDB gibi genel HTTPS servislerine erisimi bozmaz.

---

## Trend Micro TippingPoint SMS Entegrasyonu (opsiyonel)

`blacklist-ip`, `blacklist-domain` ve `blacklist-url` listelerindeki kayitlari
TippingPoint SMS'in Reputation Database'ine, belirlenen tag kategorisiyle
(varsayilan: `BlackList` = `Blacklist`) ekler. Hash girisleri SMS Web API'de
desteklenmez, bu entegrasyona dahil degildir.

**Entegrasyonlar** sayfasi → Trend Micro TippingPoint SMS Entegrasyonu karti:
1. **Aktif** kutusunu isaretle
2. **SMS Sunucu Adresi** gir (IP veya hostname)
3. **API Key** gir (SMS Client → Admin → Authentication and Authorization →
   Users → Edit → Authentication → API Key)
4. **Tag Kategorisi** ve **Tag Degeri** gir — bu tag'in SMS uzerinde onceden
   olusturulmus olmasi gerekir (Profiles → Reputation Database → Tag
   Categories)
5. SMS yonetim arayuzu ozel sertifika yuklenmediyse **SSL sertifika
   dogrulamasini atla** kutusunu isaretle (varsayilan self-signed sertifika
   kullanir)
6. **Otomatik Sync** isaretle, kaydet, **Baglanti Testi** ile dogrula
7. Mevcut kayitlari toplu gondermek icin **TippingPoint'e Senkronize Et**

> IoCManager sadece kaydi Reputation Database'e tag'leyerek ekler. Bu tag'i
> referans alan bir **Reputation Filtresi** olusturup (Profiles → Reputation/
> Geo → New Reputation) ilgili profile eklemek ve cihazlara dagitmak
> TippingPoint SMS tarafinda ayri bir adimdir.

---

## Kaldirma

```powershell
Stop-Service IoCManager
$nssm = "C:\IoCManager\nssm\nssm-2.24\win64\nssm.exe"
& $nssm remove IoCManager confirm
Remove-NetFirewallRule -DisplayName "IoCManager"
Remove-Item C:\IoCManager -Recurse -Force
# Feed dosyalarini silmek istersen (dikkat, FortiGate/Umbrella kullaniyor olabilir):
# Remove-Item C:\ThreatFeed -Recurse -Force
```
