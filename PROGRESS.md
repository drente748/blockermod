# سجل التقدم

هذا الملف يمثّل **الحالة الحالية** للمشروع فقط. يُعاد كتابته بعد كل جولة بحيث لا تبقى آثار سابقة.

## الحالة

| البند | القيمة |
|---|---|
| المرحلة | 1 — محرك الحجب (الموجة 5 من 5 مكتملة) |
| الوحدات | `:core` (Kotlin/JVM خالص) و`:app` (أندرويد) |
| الاختبارات | **122 اختبارًا** في `:core` و`:app`، بلا فشل |
| Lint | 0 خطأ (تحذير واحد: أيقونة التطبيق، مرحلة الهوية) |
| الوثائق | `docs/ARCHITECTURE.md`، `docs/PERF_CONTRACT.md`، `docs/MANUAL_TESTS.md`، `docs/LICENSE_DECISIONS.md`، `docs/THIRD_PARTY_NOTICES.md` |
| بناء APK | يعمل (`assembleDebug` و`assembleRelease`) |
| التوزيع | لا شيء منشور بعد |

## آخر تعديلات هذه الجولة (الموجة 5)

- **توليد جدول SafeSearch وقت البناء**: `tools/build-safesearch.sh` يبني `app/src/main/assets/safesearch.json`
  من خمسة مصادر فقط (S1–S5): لقطة نطاقات Google الرسمية (187 نطاقًا إقليميًا ⇒ `www.<domain>`)،
  Bing، DuckDuckGo، Brave، YouTube — **197 مدخلًا**، بمطابقة exact بلا تخمين.
- **لُقطة نطاقات Google**: `tools/supported-domains-google.txt` (مأخوذة من `google.com/supported_domains`
  بتاريخ 2026-11-15) — لقطة ثابتة تُقرأ وقت البناء، بلا تنزيل وقت التشغيل.
- **`STRICT_RESOLVER_IPS` معطّل افتراضيًا**: `StrictResolverIps.STRICT_RESOLVER_IPS_ENABLED = false`،
  وقائمة العناوين فارغة حتى قرار الترخيص؛ الميزة توثّق أثرها على البطارية في
  `docs/ARCHITECTURE.md` و`docs/PERF_CONTRACT.md`.
- **الوثائق النهائية**: `docs/ARCHITECTURE.md` (نُقل من الجذر، وبأقسام Routing Model وSafeSearch
  Rewrite وData Pipeline & License Gate وPerformance Contract وLockout (Planned))، و
  `docs/MANUAL_TESTS.md` بست مجموعات اختبار يدوي مع حالة كل مجموعة.
- **تصحيح تناقض DNS**: إسقاط 853/443 صار مقيّدًا بعناوين الـ resolvers الموجَّهة فقط، وعمومًا لا
  يُحظر التشفير داخل النفق (النفق يلتقط عنوان DNS الافتراضي فقط)، مع توثيق أن DNS/53 مستثنى من
  `ACCESS_LOCAL_NETWORK`.

## ما هو موجود في المشروع فعليًا

### `:core` — منطق خالص بلا أندرويد

- **العقود**: `BlockingEngine` (`state`/`start()`/`stop()`/`evaluate(domain)`)، `BlockingResult`
  (`Allowed`/`Blocked(reason)`/`Rewrite(target, original)`/`Error(message)`)، `BlockReason`، `BlockingState`،
  `DomainMatcher`، `SafeSearchTable`، `LockoutPolicy` + `NoOpLockoutPolicy`.
- **المحرّك**: `policy/PolicyEngine` بثمانية مسارات مرتبة + fail-safe عند التهيئة.
- **المطابقة**: `matcher/BinarySearchDomainMatcher` (بحث ثنائي على `ByteBuffer`)،
  `matcher/InMemoryDomainMatcher`، و`matcher/DomainNormalizer` (تطبيع مشترك).
- **البروتوكول**: `dns/DnsCodec` (تحليل الاستعلامات وبناء الردود، مؤشرات ضغط بحدّ 10 قفزات) و
  `net/Ipv4UdpCodec` (ترميز IPv4/UDP مع تحقّق الـ checksums).

### `:app` — تكامل النظام

- **الخدمة والنفق**: `platform/vpn/BlockerVpnService` (Builder بمسار /32 واحد، `startForeground` قبل
  `establish`، `onRevoke` ⇒ إيقاف نظيف ⇒ `Idle`، كشف Private DNS عبر `LinkProperties`)،
  `platform/vpn/VpnTunnel` (خيط قراءة + 8 عمّال + طابور 1024 + خيط latch بلا polling)،
  `platform/vpn/DnsResponder` (قرار ⇒ رد DNS)، `platform/vpn/UpstreamResolver` (Do53 إلى خوادم الشبكة
  النشطة، ربط المقبس قبل connect)، `platform/vpn/DnsCache` (LRU 512، TTL 30–300)،
  `platform/vpn/DnsWire` (بناء الاستعلام وقراءة إجابات upstream)، `platform/vpn/DecisionTrail`،
  `platform/vpn/StrictResolverIps` (معطّل).
- **العقود غير المفعّلة**: `platform/deviceowner/DeviceOwnerManager`، `platform/applock/AppLockManager`.
- **الأصول**: `blocklist.bin` + `blocklist.meta` (عنصر نائب للاختبار)، `safesearch.json` (197 مدخلًا).
- **الأدوات**: `tools/build-blocklist.sh` (بوابة ترخيص صارمة، خروج 2 قبل أي تنزيل)،
  `tools/build-safesearch.sh`، `tools/sources.tsv`، `tools/allowlist.txt`، `tools/safesearch-hosts.txt`،
  `tools/placeholder-domains.txt`، `tools/supported-domains-google.txt`.
- **خط الأنابيب**: `.github/workflows/android.yml` (بناء + اختبار + تسعة فحوص `grep` تفشل البناء).

## المرحلة 1 — محرك الحجب

| الموجة | الحالة | المحتوى |
|---|---|---|
| W1 — الأساس النقي | مكتملة | محلّل DNS، مرمّز IPv4/UDP، مطابق على `ByteBuffer`، عقد القفل، اختبارات |
| W2 — سياسة القرار | مكتملة | `Rewrite`، ترتيب السياسة الثمانية، جدول SafeSearch، دمج `LockoutPolicy` |
| W3 — النفق | مكتملة | `BlockerVpnService` كامل (DNS فقط)، pool محدود، LRU، فحوص CI، `docs/PERF_CONTRACT.md` |
| W4 — خط البيانات | مكتملة | سكريبت بناء `blocklist.bin`، بوابة ترخيص، قالبا الإشعارات، عنصر نائب |
| W5 — SafeSearch والتوثيق | مكتملة | توليد جدول SafeSearch، `STRICT_RESOLVER_IPS` معطّل، `docs/MANUAL_TESTS.md`، الوثائق النهائية |

## المرحلة 2 — الواجهة

- [ ] شاشة واحدة: تشغيل/إيقاف + حالة المحرك + تحذير Private DNS.
- [ ] إشعار دائم يوضّح أن الحماية تعمل.
- [ ] قراءة `safesearch.json` و`blocklist.bin` من الأصول وربطهما بالمحرّك.
- [ ] الثيم: Material 3 على الأقل، بلا أصول خارجية.

## المرحلة 3 — التوزيع

- [ ] APK موقّع + نسخة release مع R8.
- [ ] اختبار على جهاز فعلي وفق `docs/MANUAL_TESTS.md`.
- [ ] قرار التراخيص وإنتاج قوائم حقيقية.

## التحقق الحالي

| # | الأمر | النتيجة |
|---|---|---|
| 1 | `./gradlew :core:test` | SUCCESS — اختبارات JVM |
| 2 | `./gradlew :app:testDebugUnitTest` | SUCCESS — اختبارات وحدة التطبيق (النفق، الرد، المخبأة) |
| 3 | `./gradlew :app:assembleDebug` | SUCCESS |
| 4 | `./gradlew :app:assembleRelease` | SUCCESS |
| 5 | `./gradlew :app:lintDebug` | SUCCESS — 0 خطأ، تحذير `MissingApplicationIcon` فقط |
| 6 | فحوص `grep` في CI | 0 نتائج في التسعة فحوص |
| 7 | `bash -n tools/build-blocklist.sh` | صياغة صحيحة (السكريبت نفسه لم يُنفَّذ: بوابة الترخيص تُخرج 2 قبل أي تنزيل) |
| 8 | `tools/build-safesearch.sh` | نجح (قراءة محلية فقط) ⇒ 197 مدخلًا |

## قرارات ثابتة

- **وضع تشغيل واحد**: نفق DNS محلي (لا root ولا Device Owner ولا فلترة متصفح).
- **وحدتان باتجاه واحد** `:app → :core`؛ بلا إطار DI، بلا انعكاس، بلا كود ديناميكي.
- **بلا اتصال خدمي**: القواعد داخل التطبيق، والتحديث بتثبيت APK يدويًا.
- **النسخ الاحتياطي معطّل** على كل الإصدارات.
- **بوابة الترخيص قبل التنزيل**: أي مصدر قراره ليس `auto-allowed` ⇒ `NEEDS HUMAN` وخروج بالرمز 2.
- **`STRICT_RESOLVER_IPS` معطّل** حتى قرار الترخيص؛ قائمة العناوين فارغة الآن.
- **`Lockout` مخطط له**: العقد في `:core`، والتنفيذ مؤجّل لموجة لاحقة بلا تغيير على W1–W5.
- **R8 والتصغير مؤجّلان** حتى المرحلة 3.
