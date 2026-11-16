# عقد الأداء (R1 - R11)

هذه الوثيقة تصف قواعد الأداء وسلوك النفق التي يجب أن يلتزم بها محرك الحجب. كل قاعدة لها آلية
فرض ميكانيكية: إما كود مكتوب، أو اختبار وحدة، أو فحص `grep` يعمل في خط الأنابيب.

آخر تحديث: هذه الوثيقة تصف الحالة الراهنة للمشروع.

## القواعد

| # | القاعدة | آلية الفرض | الملف |
|---|---|---|---|
| R1 | الوضع الافتراضي: نفق DNS بمسار `/32`. الوضع التجريبي «Full tunnel» يضيف `0.0.0.0/0` لالتقاط كل IPv4 | كود + إعداد مستخدم | `BlockerVpnService.kt`، `AppSettings.kt` |
| R2 | الخدمة الأمامية معلنة بنوع صريح مع صلاحية `BIND_VPN_SERVICE` و`SUPPORTS_ALWAYS_ON` | كود + فحص `lint` | `app/src/main/AndroidManifest.xml` |
| R3 | لا استهلاك معالج أثناء الانتظار: القراءة محجوبة (`setBlocking(true)`) والخيط ينتظر على `CountDownLatch` | كود + اختبار وحدة + `grep` (لا `sleep`) | `app/src/main/java/com/blockermod/platform/vpn/VpnTunnel.kt` |
| R4 | بلا آليات جدولة أو إيقاظ: لا `WakeLock` ولا `AlarmManager` ولا `WorkManager` ولا `Timer` ولا `ScheduledExecutor` ولا `postDelayed` | `grep` في CI | `app/src/main/java/com/blockermod/platform/vpn/` |
| R5 | بلا وصول عميق لتطبيقات أخرى: لا `AccessibilityService` ولا `UsageStatsManager` | `grep` في CI | `app/src/` |
| R6 | كل مقبس صادر يُربط بالشبكة الفيزيائية **قبل** `connect`، وخوادم upstream تُقرأ من شبكة `NOT_VPN` فقط | كود (نقطة الحقن `SocketBinder` + `NetworkRequest`) | `app/src/main/java/com/blockermod/platform/vpn/UpstreamResolver.kt`، `BlockerVpnService.kt` |
| R7 | خيوط محدودة: خيط قراءة واحد، 8 خيوط عمل، 1024 طلب معلّق كحد أقصى، مهلة upstream 4 ثوانٍ | كود (ثوابت) + اختبار وحدة | `app/src/main/java/com/blockermod/platform/vpn/VpnTunnel.kt` |
| R8 | ذاكرة مخبأة: LRU بسعة قصوى 512، ومدة حياة مقصوصة بين 30 و300 ثانية، للإجابات المسموحة فقط | كود + اختبار وحدة | `app/src/main/java/com/blockermod/platform/vpn/DnsCache.kt` |
| R9 | الـ upstream هو DNS عادي (Do53) إلى خوادم الشبكة النشطة فقط، بلا fallback عام | كود + `grep` (بلا خوادم ثابتة) | `app/src/main/java/com/blockermod/platform/vpn/UpstreamResolver.kt` |
| R10 | بلا عناوين SafeSearch مكتوبة في الكود، وبلا تنسيق سجلات داخل مسار الحزم | `grep` في CI (أربعة فحوص) | `app/src/main/java/com/blockermod/platform/vpn/` |
| R11 | دورة حياة: `startForeground` قبل `establish`، و`onRevoke` يوقف النفق نظيفًا ويعيده إلى `Idle`، وكشف Private DNS عبر `LinkProperties` | كود + اختبار وحدة | `app/src/main/java/com/blockermod/platform/vpn/BlockerVpnService.kt` |

## تفاصيل إضافية

- **نفق DNS فقط**: لا تمر أي حركة أخرى للجهاز عبر النفق؛ بقية حركة الجهاز تبقى على شبكته العادية.
- **فشل مغلق (fail closed)**: تعذّر حل هدف الـ rewrite أو الـ upstream ينتج `SERVFAIL`، ولا يعود
  الطلب إلى الاسم الأصلي.
- **وضع LOG_ONLY**: يحل كل استعلام، ويسجّل القرار، ولا يحجب شيئًا. التسجيل يتم في `DecisionTrail`
  بلا تنسيق نصوص داخل مسار الحزم، والتنسيق يحدث عند إيقاف النفق.
- **TCP على منفذ 53**: خارج النطاق؛ يُعدّ ولا يُخدم (الردّ الصحيح برمجيًا هو `TC=1` لكن النفق
  لا يخدم TCP).
- **الحظر الصارم للعناوين (Strict Resolver IPs)**: **مفعّل**
  (`StrictResolverIps.STRICT_RESOLVER_IPS_ENABLED = true`) بـ 12 عنوان حلّال عام. تُوجَّه هذه
  العناوين إلى النفق ويُسقط عليها كل منفذ إلا 53 (أي 853 و 443)، **قبل** فحص منفذ DNS حتى لا يكون
  الحكم كودًا ميتًا. هذا **يزيد استهلاك البطارية** لأن النفق يقرأ حزمًا أكثر؛ مقبول مقابل منع
  تجاوز الحجب عبر الحلّالات المشفّرة المعروفة. Private DNS إلى مضيف مخصّص يبقى خارج النطاق ويُحذَّر
  منه في الواجهة.
- **ترتيب السياسة**: يمر القرار بثمانية مسارات مرتبة (قفل المستخدم، canary، SafeSearch، القائمة
  البيضاء، قائمة الإباحية، قائمة الالتفاف، قائمة المحركات غير المدعومة، السماح) — موثّق في
  `docs/ARCHITECTURE.md`.
- **ممارسات البطارية/الأداء المطبّقة**:
  - مقبس UDP واحد مُعاد استخدامه لكل استعلامات الـ upstream (`ReusableDnsSocket`) بدل مقبس لكل طلب.
  - `setUnderlyingNetworks` مُثبَّت ومُحدَّث مع الشبكة الفيزيائية حتى لا تبقى شبكتان مرفوعتين.
  - تخزين سلبي 60 ثانية لـ NXDOMAIN/NODATA لتقليل رحلات الشبكة.
  - فحص سلسلة CNAME (`cloaksBlockedDomain`) لسدّ تجاوز الحجب عبر CNAME cloaking.
  - `setBlocking(true)` + خيط قراءة واحد + latch (لا polling) + لا wake locks (R3/R4).

## الفحوص التي تعمل في CI

| الفحص | ما يرفضه |
|---|---|
| R1 | مسار افتراضي (`0.0.0.0/0` أو `::/0`) |
| R4 | آلية جدولة أو إيقاظ داخل النفق |
| R5 | وصول عميق لتطبيقات أخرى |
| R10 | اسم مضيف SafeSearch مكتوب في الكود |
| R10 | خادم DNS عام مكتوب في الكود |
| R6 | مكتبة عميل شبكة (OkHttp، Retrofit، Ktor، HttpURLConnection، URL، Socket) |
| R3 | `Thread.sleep` أو `SystemClock.sleep` داخل مصادر التطبيق |
| R10 | `Log` أو `println` داخل ملفات مسار الحزم |
| — | رابط خارجي داخل مصادر الكود |

الفحوص تعمل على المسارات الفعلية للمشروع:
`app/src/main/java/com/blockermod/platform/vpn/` (المسار المذكور في الموجّه كان `app/platform/vpn/`).
