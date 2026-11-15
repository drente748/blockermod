# قرارات التراخيص

كل مصدر يُبنى منه `blocklist.bin` يجب أن يكون له ترخيص واضح ومقبول قبل استخدامه. هذا الملف هو
سجل تلك القرارات: **لا يُبنى أي مصدر قبل أن تكون قراراته هنا**.

القواعد:

- القرار `auto-allowed` يعني أن الترخيص مسموح صراحة (MIT، Apache-2.0، BSD، أو ترخيص يذكر
  الحظر والإسناد) **ويجب** تسجيل رابط ملف الترخيص/shasum يوم واضح.
- القرار `NEEDS HUMAN` يعني أن الترخيص لم يُتحقق منه بعد: **يُرفض المصدر** ويخرج سكريبت البناء
  بالرمز `2` قبل أي تنزيل.
- لا يُخمَّن ترخيص ولا يُنسخ من مستودع آخر. التحقق مسؤولية إنسان.
- تغيير أي صف هنا هو قرار واعٍ: يُسجَّل هنا بتاريخ واسم منوافق.

## الحالة الراهنة: كل المصادر تنتظر قرارًا بشريًا

| المصدر | URL | commit SHA | ملف الترخيص الذي رُئي | القرار | الموافق | التاريخ |
|---|---|---|---|---|---|---|
| ha-casco | https://github.com/HaCasco/ha-blocklist | TBD | لم يُتحقق منه | **NEEDS HUMAN** | — | — |
| steven-black | https://github.com/StevenBlack/hosts | TBD | لم يُتحقق منه | **NEEDS HUMAN** | — | — |
| adguard-filters | https://github.com/AdguardTeam/AdGuardFilters | TBD | لم يُتحقق منه | **NEEDS HUMAN** | — | — |
| hostlists-registry | https://github.com/AdguardTeam/HostlistsRegistry | TBD | لم يُتحقق منه | **NEEDS HUMAN** | — | — |
| firehol-ipsets | https://github.com/firehol/blocklist-ipsets | TBD | لم يُتحقق منه | **NEEDS HUMAN** | — | — |
| energized-unblock | https://github.com/EnergizedProtection/Unblock-YouTube-Adblockers-Filter | TBD | لم يُتحقق منه | **NEEDS HUMAN** | — | — |

**النتيجة الآن**: `tools/build-blocklist.sh` يخرج بالرمز `2` (ترخيص غير محسوم) قبل أي تنزيل، وهذا
هو السلوك المطلوب.

## ما يجب فعله لكل مصدر

1. قراءة ملف الترخيص في commit المحدد (لا في فرع متحرك).
2. التأكد من أن الترخيص يسمح بإعادة التوزيع داخل تطبيق، وأن ذكر المصدر إلزامي عند الحاجة.
3. تثبيت commit SHA وSHA-256 للملف المُنزَّل في `tools/sources.tsv`.
4. تحويل القرار إلى `auto-allowed` هنا مع اسم الموافق والتاريخ.
5. إعادة بناء `blocklist.bin` والتحقق من ثبات الـ SHA-256.
