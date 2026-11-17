# إشعارات الأطراف الثالثة

هذا الملف يسجّل مصادر قوائم الحظر المبنية في التطبيق. في كل صف: اسم المصدر، رابطه،
commit المستخدم، ترخيصه، عدد النطاقات المساهمة، وبصمة الملف الناتج.

**الحالة الراهنة: قوائم حقيقية مبنية ومشمولة في التطبيق.**

## blocklist.bin — حظر الإباحية (154,844 نطاقًا)

| الاسم | URL | commit | الترخيص |
|---|---|---|---|
| StevenBlack/hosts (porn) | https://github.com/StevenBlack/hosts | ce25ce24d6dca08fa484612091a822bc93587086 | MIT |
| StevenBlack/hosts (porn-only) | https://github.com/StevenBlack/hosts | ce25ce24d6dca08fa484612091a822bc93587086 | MIT |
| Potterfanz/Stricter-porn-blocklist | https://github.com/Potterfanz/Stricter-porn-blocklist | c7b8e375a0491f040d34f018a1cbb74edc188981 | MIT |
| HaGeZi NSFW | https://github.com/hagezi/dns-blocklists | 071064f08e7b2a39d59e0bf221de3c54555d2486 | GPL-3.0 (بيانات) |

## bypass.bin — محاولات الالتفاف / DNS مشفر (16,458 نطاقًا)

| الاسم | URL | commit | الترخيص |
|---|---|---|---|
| HaGeZi DoH/VPN/Proxy Bypass | https://github.com/hagezi/dns-blocklists | 071064f08e7b2a39d59e0bf221de3c54555d2486 | GPL-3.0 (بيانات) |

## unsupported.bin — محركات بحث لا تدعم SafeSearch (202 نطاقًا)

| الاسم | URL | commit | الترخيص |
|---|---|---|---|
| HaGeZi NoSafeSearch | https://github.com/hagezi/dns-blocklists | 071064f08e7b2a39d59e0bf221de3c54555d2486 | GPL-3.0 (بيانات) |

> المصادر مستخدمة لقوائم الحظر داخل التطبيق، «كما هي» بعد التطبيع والإزالة الآلية فقط.
>
> **StevenBlack/hosts:** Copyright © 2026 Steven Black — MIT License.
> **Potterfanz/Stricter-porn-blocklist:** MIT License.
> **HaGeZi DNS Blocklists:** Copyright © hagezi — GNU General Public License v3.0. تُدمج قوائمه
> كبيانات نطاقات فقط في أصول `.bin` منفصلة عن كود التطبيق (Apache-2.0)، مع هذا الإسناد الكامل.
> النص الكامل لترخيص GPL-3.0 متاح في المستودع: https://www.gnu.org/licenses/gpl-3.0.html
>
> البصمات (SHA-256) وعدد المدخلات لكل ملف في `app/src/main/assets/*.meta`.
