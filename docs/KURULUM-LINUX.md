# IoCManager v1.6 — Ubuntu Kurulumu

Ubuntu 20.04 / 22.04 / 24.04 icin test edilmistir.

---

## Hizli Kurulum (3 adim)

**1.** Bu repo'yu (`git clone` ile veya scp/rsync ile) sunucuya kopyala

**2.** Klasore gir:
```bash
cd iocmanager/linux
```

**3.** Kurulumu calistir:
```bash
sudo bash kurulum.sh
```

Script otomatik olarak:
- `python3`, `venv`, `pip`, `ufw` paketlerini kurar
- `iocmanager` sistem kullanicisi olusturur (shell'siz, guvenli)
- `/opt/iocmanager` ve `/opt/threatfeed/public` dizinlerini olusturur
- Python sanal ortami (venv) kurar, Flask + Gunicorn yukler
- Dosya izinlerini ayarlar
- Firewall'da 5000 portunu acar (ufw)
- systemd servisini kurar, etkinlestirir ve baslatir

---

## Kurulum Sonrasi

```
Portal : http://SUNUCU_IP:5000
Giris  : admin / IoCManager2026!
```

**Ilk giriste sifreyi degistir** — nav menusunden "Sifre Degistir".

---

## Sistem Izleme Ekrani

**Izleme** sekmesi (sadece admin) uygulamanin kendi icinden servis sagligini
gosterir:

- **Servis durumu** — `systemctl is-active iocmanager` ile canli sorgulanir
- **Uptime** — bu worker'in ne zamandir ayakta oldugu (servis yeniden
  baslarsa sifirlanir)
- **Veritabani** erisim durumu ve boyutu
- **Feed dosyalari** — her birinin kayit sayisi, boyutu, son guncelleme zamani
- **Son 24 saat aktivite** — ekleme/silme/giris/basarisiz giris sayilari
- **Log Goruntuleyici** — `access.log`, `error.log` (gunicorn) ve
  `iocmanager-cef.log` dosyalarinin son N satirini dogrudan tarayicidan
  gosterir

Bu ekran, `journalctl -u iocmanager`'a gitmeden gecmise donuk hata
arastirmasi yapmani saglar.

---

## Dizin Yapisi

```
/opt/iocmanager/
├── app.py
├── run.py                  ← sadece manuel test icin, servis bunu kullanmaz
├── venv/                   ← Python sanal ortami
├── templates/
├── static/
├── data/
│   └── iocmanager.db       ← kullanicilar, audit log, ayarlar, API anahtarlari
└── logs/
    ├── access.log          ← gunicorn erisim logu
    ├── error.log           ← gunicorn hata logu
    └── iocmanager-cef.log  ← SIEM CEF logu

/opt/threatfeed/public/     ← FortiGate/Umbrella'nin cektigi feed dosyalari
├── allowlist-ip.txt
├── blacklist-ip.txt
├── blacklist-hash.txt
├── allowlist-domain.txt
├── blacklist-domain.txt
├── allowlist-url.txt
└── blacklist-url.txt
```

---

## Servis Yonetimi

```bash
sudo systemctl status  iocmanager      # durum
sudo systemctl start   iocmanager
sudo systemctl stop    iocmanager
sudo systemctl restart iocmanager
sudo journalctl -u iocmanager -f       # canli log takibi
sudo journalctl -u iocmanager -n 100 --no-pager   # son 100 satir
```

Servis `iocmanager` adinda ayri, shell'siz bir sistem kullanicisi altinda calisir —
root olarak calismaz. `systemd` ayrica `ProtectSystem=strict` ve benzeri
sertlestirme ayarlariyla dosya sistemine erisimi sadece gerekli dizinlerle
sinirlar (`ReadWritePaths`).

---

## Guncelleme (kod degisince)

Sadece uygulama dosyalarini degistirip servisi yeniden baslat — veritabani ve
feed dosyalarina dokunulmaz. Komutlari **repo kokunden** (linux/ klasorunun
bir ustunden) calistir:

```bash
cd ..   # linux/ klasorundeysen repo kokune cik
sudo systemctl stop iocmanager
sudo cp app.py /opt/iocmanager/app.py
sudo cp -r templates/. /opt/iocmanager/templates/
sudo chown -R iocmanager:iocmanager /opt/iocmanager
sudo systemctl start iocmanager
```

---

## Manuel Test (systemd disinda)

Sorun gidermek icin servisi durdurup elle calistirmak istersen:

```bash
sudo systemctl stop iocmanager
cd /opt/iocmanager
sudo -u iocmanager IOCMANAGER_FEED_DIR=/opt/threatfeed/public \
     IOCMANAGER_DB=/opt/iocmanager/data/iocmanager.db \
     venv/bin/python run.py
```

Bitince `Ctrl+C`, sonra tekrar `sudo systemctl start iocmanager`.

---

## Threat Intel API (Sorgu sekmesi)

**Entegrasyonlar** sayfasi → Threat Intel API Anahtarlari karti uzerinden
VirusTotal, AbuseIPDB, URLScan, Shodan, MXToolbox anahtarlarini girebilirsiniz.
Anahtar girilen kaynaklar **Sorgu** sekmesinde (tum kullanicilara acik) aktif
olur; bos birakilan kaynaklar sessizce atlanir. URLScan icin ekran goruntusu
gosterilmez, sadece metinsel sonuclar sunulur.

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
Cozum, kurumsal kok sertifikayi Python'a tanitmak:

1. **Kok sertifikayi al** — tarayicidan `https://api.umbrella.com` icin
   sertifika zincirinin en ustundeki (root) sertifikayi `.pem`/`.crt`
   formatinda export et, ya da IT'den iste.

2. **Sunucuya kopyala:**
   ```bash
   sudo cp kurumsal-ca.crt /opt/iocmanager/corp-ca.pem
   sudo chown iocmanager:iocmanager /opt/iocmanager/corp-ca.pem
   ```

3. **Servise ortam degiskeni olarak tanit:**
   ```bash
   echo "IOCMANAGER_CA_BUNDLE=/opt/iocmanager/corp-ca.pem" | sudo tee -a /opt/iocmanager/.env
   sudo chown iocmanager:iocmanager /opt/iocmanager/.env
   sudo systemctl restart iocmanager
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
desteklenmez.

**Entegrasyonlar** sayfasi → Trend Micro TippingPoint SMS Entegrasyonu karti:
1. **Aktif** kutusunu isaretle
2. **SMS Sunucu Adresi** ve **API Key** gir (SMS Client → Admin →
   Authentication and Authorization → Users → Edit → Authentication → API Key)
3. **Tag Kategorisi/Degeri** gir — SMS uzerinde onceden olusturulmus olmali
4. SMS ozel sertifika yuklenmediyse **SSL sertifika dogrulamasini atla**
   kutusunu isaretle
5. **Otomatik Sync** isaretle, kaydet, **Baglanti Testi** ile dogrula
6. Mevcut kayitlari toplu gondermek icin **TippingPoint'e Senkronize Et**

> Tag'i referans alan bir **Reputation Filtresi** olusturup profile eklemek
> ve cihazlara dagitmak TippingPoint SMS tarafinda ayri bir adimdir.

---

## Kaldirma

```bash
sudo systemctl stop iocmanager
sudo systemctl disable iocmanager
sudo rm /etc/systemd/system/iocmanager.service
sudo systemctl daemon-reload
sudo ufw delete allow 5000/tcp
sudo userdel iocmanager
sudo rm -rf /opt/iocmanager
# Feed dosyalarini silmek istersen (dikkat, FortiGate/Umbrella kullaniyor olabilir):
# sudo rm -rf /opt/threatfeed
```

---

## Ortam Degiskenleri (opsiyonel ozellestirme)

`/opt/iocmanager/.env` dosyasi olusturursan systemd bunu otomatik okur:

```bash
sudo tee /opt/iocmanager/.env << 'EOF'
SECRET_KEY=guclu-rastgele-bir-deger-buraya
EOF
sudo chown iocmanager:iocmanager /opt/iocmanager/.env
sudo chmod 600 /opt/iocmanager/.env
sudo systemctl restart iocmanager
```

`SECRET_KEY` ayarlanmazsa uygulama her yeniden baslatmada rastgele bir tane
uretir — bu, o oturumdan once acik kalan session'larin gecersiz olmasina
sebep olabilir. Kalici bir deger vermek onerilir.
