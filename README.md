# kit-check

وقتی فیلترینگ سخت‌تر میشه و فیلترشکنت قطع میشه، این اسکریپت روی اینترنت خودت تست می‌کنه کدوم راه هنوز بازه، تا به‌جای امتحان کردن ده تا برنامه، بدونی سراغ کدوم بری.
English version: [below](#english)

آموزش ویدیویی (فارسی): کانال یوتیوب [@V7lthronyx](https://www.youtube.com/@V7lthronyx)

## نردبون پنج‌پله

| پله | چی هنوز بازه | چی امتحان کنی |
|---|---|---|
| ۱ | فیلترینگ معمولی | سرور خودت (REALITY و بقیه) |
| ۲ | آی‌پی سرورت بسته شده | کانفیگ پشت کلودفلر، آی‌پی تمیز |
| ۳ | فقط سرویس‌های بزرگ | اسنوفلیک و وب‌تانل تور، سایفون |
| ۴ | فقط DNS اینترنت‌سرویس | تونل DNS |
| ۵ | خاموشی کامل | هیچ‌کدوم از این‌ها |

پله‌ی ۵ رو صادقانه بگیم: توی خاموشی کامل، هیچ ابزاری که از اینترنت کشور رد میشه کار نمی‌کنه. این کیت برای قبل از اون لحظه‌ست.

## چی رو تست می‌کنه

| خط | تست |
|---|---|
| `dns` | DNS گوشی یا کامپیوترت هنوز اسم‌های خارجی رو جواب میده؟ جواب‌های جعلی (مثل `10.10.34.x`) رو هم می‌شناسه |
| `dns-out` | DNS معمولی (UDP پورت ۵۳) به 1.1.1.1، 8.8.8.8 و 9.9.9.9 |
| `doh` | DNS روی HTTPS به cloudflare-dns.com و dns.google |
| `server` | اتصال TCP و دست‌دادن TLS با سرور خودت، با همون SNI کانفیگت |
| `cdn` | TLS و صفحه‌ی `/cdn-cgi/trace` روی دامنه‌ی کلودفلرت (اسم دیتاسنتر رو هم نشون میده) |
| `tunnel` | یه سؤال DNS به دامنه‌ی تونلت از راه DNS اینترنت‌سرویس؛ اگه به سرور dnstt برسه، جوابش فرق داره |

آخرش یه خط میگه الان روی کدوم پله‌ای و چی رو امتحان کنی.

```
  ok     dns      example.com resolves (system resolver)
  block  dns-out  udp/53 to 1.1.1.1, 8.8.8.8, 9.9.9.9: no answer
  block  doh      cloudflare-dns.com, dns.google: timeout
  block  server   203.0.113.7:443: tcp timeout
  block  cdn      sub.example.com: tcp timeout
  ok     tunnel   t.example.com answers via 10.20.30.40
rung 4 of 5: only DNS gets out: use a DNS tunnel
```

فقط به سه DNS عمومی بالا و آدرس‌هایی که خودت بهش میدی وصل میشه. چیزی رو اسکن نمی‌کنه و هیچ‌جا چیزی نمی‌فرسته. فقط یه فایل پایتون، بدون هیچ کتابخونه‌ی اضافه (پایتون ۳.۸ یا جدیدتر).

## قبل از اجرا: فیلترشکن رو خاموش کن

باید از روی همون اینترنتی اجرا بشه که گیر کردی (دیتای گوشی، وای‌فای خونه). اگه فیلترشکن روشن باشه، داری مسیر فیلترشکن رو تست می‌کنی، نه اینترنت خودت رو.

## فایل لینک‌ها

لینک کانفیگ‌هات رو توی یه فایل متنی بذار، هر کدوم یه خط. اسکریپت از روی خود لینک می‌فهمه چی رو تست کنه:

```
vless://...@203.0.113.7:443?security=reality&sni=www.example.com&...#my-server
vless://...@sub.example.com:443?security=tls&sni=sub.example.com&type=ws&...#cdn
tunnel t.example.com
```

- لینک `security=reality` میشه تست `server`
- لینک `security=tls` (یا `trojan://`) میشه تست `cdn`؛ اگه توی لینک آی‌پی تمیز گذاشتی، با همون آی‌پی تست میشه
- خط `tunnel` دامنه‌ی تونل DNS خودته (همون اسمی که رکورد NS داره)
- از هر نوع فقط اولین خط تست میشه. خط‌هایی که با `#` شروع میشن نادیده گرفته میشن.

لینک‌هات از گوشی یا کامپیوترت جایی نمیرن.

## دانلود و اجرا

### اندروید (Termux)

Termux رو از F-Droid یا گیت‌هاب خودش نصب کن. بعد:

```
pkg install python curl
curl -fsSLO https://raw.githubusercontent.com/v74all/kit-check/v1.0.0/kit-check.py
curl -fsSLO https://raw.githubusercontent.com/v74all/kit-check/v1.0.0/kit-check.py.sha256
sha256sum -c kit-check.py.sha256
python kit-check.py links.txt
```

فایل لینک‌ها رو با `nano links.txt` بساز.

### ویندوز (PowerShell)

پایتون رو از python.org نصب کن (تیک Add to PATH). بعد:

```
curl.exe -fsSLO https://raw.githubusercontent.com/v74all/kit-check/v1.0.0/kit-check.py
curl.exe -fsSLO https://raw.githubusercontent.com/v74all/kit-check/v1.0.0/kit-check.py.sha256
Get-FileHash kit-check.py
type kit-check.py.sha256
py kit-check.py links.txt
```

دو تا هش باید یکی باشن.

### لینوکس و مک

```
curl -fsSLO https://raw.githubusercontent.com/v74all/kit-check/v1.0.0/kit-check.py
curl -fsSLO https://raw.githubusercontent.com/v74all/kit-check/v1.0.0/kit-check.py.sha256
sha256sum -c kit-check.py.sha256        # macOS: shasum -a 256 -c kit-check.py.sha256
python3 kit-check.py links.txt
```

### بدون فایل

```
python3 kit-check.py --server 203.0.113.7 --sni www.example.com --cdn sub.example.com --tunnel t.example.com
```

`--resolver IP` برای تست تونل از راه یه DNS دیگه (روی ویندوز و بعضی گوشی‌ها اسکریپت DNS سیستم رو پیدا نمی‌کنه؛ آدرس DNS شبکه‌ات رو خودت بده). `--timeout` ثانیه‌ی هر تلاشه (پیش‌فرض ۴).

## محدودیت‌ها

- پله‌ی ۳ یه حدسه: اگه سرویس‌های بزرگ هنوز جواب میدن، ابزارهایی مثل اسنوفلیک و سایفون شانس دارن. خود تور و سایفون رو تست نمی‌کنه؛ باید امتحانشون کنی.
- تست `tunnel` فقط میگه سؤال‌های DNS به سرور تونلت می‌رسن یا نه. سرعت و پایداری تونل رو نمیگه.
- نتیجه مال همین لحظه و همین اینترنته. یه ساعت بعد، یا روی یه اپراتور دیگه، می‌تونه فرق کنه.

## تست

```
python3 -m unittest discover -s tests
```

## مجوز

MIT

---

## English

kit-check tells you which way out still works on the network you are on, when censorship tightens and your usual config stops working.

It checks, in parallel: whether your system resolver still answers foreign names (and spots hijacked answers such as `10.10.34.x`), plain DNS to 1.1.1.1 / 8.8.8.8 / 9.9.9.9, DNS over HTTPS to cloudflare-dns.com and dns.google, a TCP + TLS handshake to your own server with your config's SNI, TLS + `/cdn-cgi/trace` on your domain behind Cloudflare, and whether a DNS query for your tunnel domain reaches your dnstt server through your network's resolver. The last line names the highest rung that still works:

1. your own server · 2. your config behind the CDN · 3. big providers only (try Snowflake, WebTunnel, Psiphon) · 4. only DNS (a DNS tunnel) · 5. nothing international answers.

Run it with your VPN off. It only talks to the three public resolvers above and to the servers you name; it does not scan anything and sends nothing anywhere. One file, Python 3.8+ standard library only (Linux, macOS, Windows, Termux). Tested on Ubuntu 24.04 (Python 3.12), Debian 12 (3.11), Python 3.8 and 3.14.

```
python3 kit-check.py links.txt
```

`links.txt` holds your own `vless://` / `trojan://` links, one per line: a `security=reality` link becomes the server check, a `security=tls` link the CDN check (a clean IP in the link is used as the address), and a `tunnel t.example.com` line the DNS tunnel check. Flags `--server --sni --cdn --cdn-ip --tunnel --resolver --timeout` do the same without a file.

Download, checking the hash:

```
curl -fsSLO https://raw.githubusercontent.com/v74all/kit-check/v1.0.0/kit-check.py
curl -fsSLO https://raw.githubusercontent.com/v74all/kit-check/v1.0.0/kit-check.py.sha256
sha256sum -c kit-check.py.sha256
```

Limits: rung 3 is a hint, not a test of Tor or Psiphon themselves; the tunnel check says queries reach your server, not how fast the tunnel is; results hold for this network at this moment.

License: MIT
