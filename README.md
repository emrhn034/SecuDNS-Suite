# SecuDNS Suite

**Güvenlik odaklı DNS Paketi**  
Hepsi bir arada DNS tarama, zafiyet tespiti, tarihçe izleme, raporlama ve uyarı sistemi.

## Özellikler

- **DNS kayıt taraması**: A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, PTR  
- **Zone transfer kontrolü**: Nameserver’larda AXFR zafiyeti  
- **Tarihçe karşılaştırması**: Önceki kayıtlarla farkları JSON’da saklar  
- **Envanter yönetimi**: `--inventory domains.txt` ile toplu analiz  
- **Paralel sorgulama**: Eşzamanlı analiz için `ThreadPoolExecutor`  
- **Rapor üreteci**: HTML ve XLSX formatında rapor (Jinja2 & Pandas)  
- **E‑posta uyarısı**: Zone transfer açığı durumunda SMTP ile bildirim  
- **Log dosyası**: Tüm işlem adımları `dns_suite.log`’a kaydedilir

## Kurulum

1. Python 3.8+ ve pip yüklü olsun.  
2. Proje kökünde sanal ortam oluşturup etkinleştir:

   ```bash
   python3 -m venv venv
   source venv/bin/activate    # Linux/macOS
   venv\\Scripts\\activate     # Windows

Gerekli paketleri yükle:
pip install -r requirements.txt

Kullanım
Tek domain analizi
python dns_suite.py example.com \
  --zone-transfer --history --email-security


Envanter dosyasından toplu analiz
python dns_suite.py --inventory domains.txt \
  --report html --report-out report.html

Zone transfer açığı tespit edildiğinde e‑posta bildirimi
python dns_suite.py example.com --alert-email \
  --smtp-server smtp.example.com --smtp-user you@example.com \
  --smtp-pass yourpass --to-email admin@example.com






