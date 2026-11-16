# سجل التقدم

هذا الملف يمثّل **الحالة الحالية** للمشروع فقط. يُعاد كتابته بعد كل جولة بحيث لا تبقى آثار سابقة.

## الحالة

| البند | القيمة |
|---|---|
| المرحلة | 1 — محرك الحجب يعمل بقائمة حقيقية + واجهة تشغيل بسيطة (بلا ثيم/تصميم) |
| الوحدات | `:core` (Kotlin/JVM خالص) و`:app` (أندرويد) |
| الاختبارات | **145 اختبارًا** في `:core` و`:app`، بلا فشل |
| Lint | 0 أخطاء و0 تحذيرات (`No issues found`) |
| القوائم | **181,565** نطاق إباحي (`blocklist.bin`) + **16,458** نطاق تفاف/DNS مشفّر (`bypass.bin`) + **202** محرك بلا SafeSearch (`unsupported.bin`) — من 6 مصادر مثبّتة (MIT + GPL-3.0 بيانات) |
| الوثائق | `docs/ARCHITECTURE.md`، `docs/PERF_CONTRACT.md`، `docs/MANUAL_TESTS.md`، `docs/LICENSE_DECISIONS.md`، `docs/THIRD_PARTY_NOTICES.md` |
| بناء APK | يعمل (`assembleDebug`) — النسخة التجريبية: `C:\Users\pc\Desktop\opencode\blockermod-beta.apk` |
| التوزيع | لا شيء منشور بعد |

## آخر تعديلات هذه الجولة (تدقيق ما قبل الالتزام)

- `TcpRelay` يؤجّل إنشاء المقبس الحقيقي إلى ما بعد فحص SNI/DoH وDNS-over-TCP، فلا يتجاوز اتصال
  مشفّر محجوب الشبكة أبدًا. تحديد أقصى 128 اتصال TCP و128 تدفّق UDP لمنع استنفاد الخيوط/الواصفات.
- تصحيح سلوك IPv6 في النفق الكامل: `allowFamily(AF_INET6)` يسمح بمروره للشبكة الأساسية (لا يُفلتر).
- تصحيح أرقام الاختبارات القديمة في `PROGRESS.md`. 145 اختبارًا، 0 فشل.

## آخر تعديلات الجولة السابقة (استثناء أسماء الاستخدام المحلي)

- **حماية DNS rebinding صارت أذكى**: الأسماء المحجوزة للاستخدام المحلي تُسمح لها بالإشارة إلى عناوين
  خاصة، وفق المعايير: `.local` (RFC 6762)، `.home.arpa` (RFC 8375)، `localhost`/`test`/`invalid`
  (RFC 6761)، و`.lan`/`.home`/`.internal`، إضافةً إلى الأسماء أحادية التسمية. النطاقات العامة التي تشير
  إلى عنوان خاص تُرفض كما كانت. 145 اختبارًا، 0 فشل.

## آخر تعديلات الجولة السابقة (محلّل DNS محلي كامل)

- **`LocalDnsResolver`**: محلّل DNS محلي كامل يملك السياسة والكاش الإيجابي/السلبي،
  تتبّع سلاسل CNAME (حتى 5 قفزات)، حماية SafeSearch، وحماية DNS rebinding (رفض عناوين خاصة).
  يخدم **UDP وTCP** من نفس المسار — `DnsResponder` صار مجرد محوّل رفيع.
- **نقل الكاش من `UpstreamResolver` إلى `LocalDnsResolver`** (فصل الاهتمامات)؛
  `getFresh` يُعيد الـ TTL المتبقي بدل TTL الأصلي (RFC 2308).
- **EDNS(0)** في استعلامات الـ upstream بحجم 1232 بايت (RFC 6891) لتجنّب التجزئة والرجوع لـ TCP
  (توفير بطارية). التخزين السلبي 60 ثانية مطابق لتوصية RFC 2308 بعدم تجاوز TTL الإجابات الإيجابية.
- `UpstreamResolver` صار مُوجّه شبكة فقط (بلا كاش) مع مقبس واحد مُعاد استخدامه.
- 143 اختبارًا، 0 فشل.

## آخر تعديلات الجولة السابقة (محرك النفق الكامل)

بناءً على طلب صريح بعدم الالتزام بـ R1، أُضيف محرك **Full tunnel** تجريبي (مُفعّل من الإعدادات،
افتراضيًا مغلق):
- `Ipv4TcpCodec` (Core): تحليل/بناء IPv4+TCP مع checksums وخيارات MSS — 5 اختبارات جديدة.
- `TcpRelay`: استقبال SYN/SYN-ACK/ACK/PSH/FIN/RST، إعادة توجيه عبر `Socket` محمي من النفق،
  حقن الردود في النفق. يوقف DoT (853) ويفحص SNI لمنع DoH بأسماء معروفة (`TlsSniInspector`)،
  ويطبّق سياسة DNS على TCP/53.
- `UdpRelay`: إعادة توجيه UDP غير DNS عبر `DatagramSocket` محمي.
- `BlockerVpnService`: مسار `0.0.0.0/0` عند تفعيل الوضع، مع `protect()` وربط العزل،
  و`writeTunnelPacket` لحقن الحزم من خيوط الـ relay.
- الوضع الافتراضي (DNS-only) لم يتغير — الفرق في البطارية موثّق في الإعدادات.
- 136 اختبارًا، 0 فشل؛ lint نظيف؛ APK مبني.

## آخر تعديلات الجولة السابقة (البطارية + الأداء + منع الالتفاف)

بناءً على ممارسات أندرويد الرسمية لـ VpnService (`setUnderlyingNetworks`، `setBlocking`، تقليل
المسارات) وممارسات محركات DNS (إعادة استخدام المقبس، التخزين السلبي، فحص CNAME):

- **إعادة استخدام مقبس DNS** (`ReusableDnsSocket` في `UpstreamResolver`): مقبس UDP واحد مرتبط بالشبكة
  الفيزيائية يُستخدم لكل الاستعلامات بدل إنشاء مقبس لكل استعلام — يوفّر fd/binder/GC في كل طلب DNS.
  يُعاد إنشاؤه عند تغيّر الشبكة أو فشل الإرسال، ويُغلق مع الخدمة.
- **تثبيت الشبكة الأساسية**: `setUnderlyingNetworks` في `establishTunnel` ويُحدَّث من `onAvailable`/
  `onLost` حتى لا تُبقي أندرويد Wi-Fi والجوال معًا لتغذية النفق. `setSession` لتسمية الجلسة في حوار النظام.
- **تخزين سلبي** (`DnsCache.rememberNegative`/`isNegative`): NXDOMAIN وNODATA يُخزَّنان 60 ثانية،
  فلا يُعاد استعلام الاسم غير الموجود عند كل محاولة — أقل حزمة شبكة وأقل بطارية.
- **كشف CNAME cloaking** (`DnsResponder.cloaksBlockedDomain`): الاسم المسموح الذي يشير CNAME الخاص به
  إلى نطاق إباحي محجوب يُردّ بـ NXDOMAIN — يسدّ أسلوبًا شائعًا لتجاوز الحجب في المتصفحات.
- 3 اختبارات جديدة (127 الإجمالي).

## آخر تعديلات الجولة السابقة (تقوية الحجب)

- **6 مصادر متخصصة مثبّتة**: StevenBlack (porn + porn-only)، Potterfanz Stricter-porn (كلها MIT)،
  وhagezi (NSFW + DoH/VPN/Proxy Bypass + NoSafeSearch — GPL-3.0 للبيانات فقط، بقرار من المستخدم
  وتحديث السياسة في `docs/LICENSE_DECISIONS.md`). كل مجموعة بـ commit + SHA-256.
- **توسيع البناء**: `tools/build-blocklist.sh` صار يقرأ صيغة Adblock Plus (`||domain^`) وينتج ثلاث
  قوائم معبّأة: `blocklist.bin` (181,565)، `bypass.bin` (16,458)، `unsupported.bin` (202) مع ملفات
  `.meta` لكل منها.
- **تفعيل مسارات السياسة الميتة**: `createPolicyEngine` يربط الآن `bypassBlocklist` و
  `unsupportedEngineBlocklist` بقوائم حقيقية بدل مجموعات فارغة، ويفشل مغلقًا عند غياب أي قائمة.
- **إصلاح سباق الإيقاف**: `awaitStopped` ينتظر خيط الانتظار أيضًا حتى تُضبط الحالة `Idle` (كُشف
  باختبار `stopping the tunnel` بعد إصلاح EOF).
- **CI**: تضييق فحص «public resolver» على `app/src/main/java` فقط لأن عناوين الحجب الصارم أصبحت
  في أصل `strict-resolvers.txt`.

## آخر تعديلات الجولة السابقة (حجب حقيقي + تجاوز DNS مشفّر)

- **قائمة حظر حقيقية**: `tools/build-blocklist.sh` يبني الآن 114,335 نطاقًا من لقطة
  `alternates/porn/hosts` (MIT) بعد تثبيت الترخيص بقرار مالك المشروع — انظر `docs/LICENSE_DECISIONS.md`.
  حُذفت النطاقات الوهمية؛ `BlocklistTest` صار يتحقق من نطاقات حقيقية (pornhub, xvideos…).
- **ربط القائمة والقائمة البيضاء بالمحرّك**: `createPolicyEngine` يفشل مغلقًا (لا محرك بلا قائمة)،
  ويحمّل `allowlist.txt` من الأصول، ولم يعد يتجاهل مصدر القاعدة.
- **تجاوز DNS المشفّر (المسار أ)**: `STRICT_RESOLVER_IPS_ENABLED = true` مع 12 عنوان حلّال عام
  (Google/Cloudflare/Quad9/AdGuard/OpenDNS/CleanBrowsing)؛ المنفذان 853 و443 يُسقطان لها، وأُصلح
  ترتيب الفحص في `VpnTunnel` الذي كان يجعله كودًا ميتًا. تحذير Private DNS صار يُنشر فعليًا إلى
  الواجهة عبر `EngineStatus.publishPrivateDns`.
- **إصلاحات أخرى**: تجمّد واجهة بعد الخروج من الشاشة (scope)، تزامن `DnsCache` بين 8 خيوط،
  `NXDOMAIN`/`NODATA` من upstream بدل `SERVFAIL`، إعادة كتابة مؤشرات الضغط في RDATA،
  منع الدوران عند نهاية مجرى النفق، منع بدء مزدوج للخدمة، وسرب واصف القائمة.

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

## آخر تعديلات هذه الجولة (إصلاح حلقة DNS)

- **إصلاح الخطر 11**: كان `registerDefaultNetworkCallback` يجعل النفق نفسه «الشبكة الافتراضية»
  بعد `establish()`، فيُقرأ العنوان الافتراضي `10.111.222.3` كخادم upstream، فيحلّ النفق استعلاماته
  عبر نفسه (حلقة/تجمّد). الآن يُسجَّل `NetworkCallback` على `NetworkRequest` بشرط
  `NET_CAPABILITY_NOT_VPN`، وتُتجاهل أي شبكة تحمل `TRANSPORT_VPN`، ويُسقط العنوان الافتراضي من
  قائمة `dnsServers`، ويُنظَّف الخادم عند `onLost` حتى لا يبقى خادم شبكة زالت.
  الملف: `platform/vpn/BlockerVpnService.kt`، والتوثيق في `docs/ARCHITECTURE.md` (قسم 8) و
  `docs/PERF_CONTRACT.md` (R6).

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
  `platform/vpn/StrictResolverIps` (مفعّل — يحمّل العناوين من أصل ويُسقط 853/443)،
  `platform/vpn/ReusableDnsSocket` (مقبس UDP واحد مُعاد استخدامه).
- **العقود غير المفعّلة**: `platform/deviceowner/DeviceOwnerManager`، `platform/applock/AppLockManager`.
- **الأصول**: `blocklist.bin` (181,565 نطاق إباحي)، `bypass.bin` (16,458)، `unsupported.bin` (202)،
  `allowlist.txt`، `strict-resolvers.txt` (12 عنوانًا)، `safesearch.json` (197 مدخلًا)، وملفات `.meta` لكل
  قائمة. حُذفت النطاقات الوهمية بالكامل.
- **الأدوات**: `tools/build-blocklist.sh` (يقرأ hosts وAdblock Plus، بوابة ترخيص، ثلاث قوائم)،
  `tools/build-safesearch.sh`، `tools/sources.tsv` (6 مصادر مثبّتة)، `tools/allowlist.txt`،
  `tools/safesearch-hosts.txt`، `tools/supported-domains-google.txt`، `tools/perf-measure.sh`.
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
| 9 | `./gradlew :app:compileDebugKotlin :app:lintDebug` (بعد إصلاح حلقة DNS) | SUCCESS — lint: «No issues found» |
| 10 | `./gradlew :core:test :app:testDebugUnitTest` (بعد الإصلاح) | SUCCESS — 122 اختبارًا، 0 فشل |

## قرارات ثابتة

- **وضع تشغيل واحد**: نفق DNS محلي (لا root ولا Device Owner ولا فلترة متصفح).
- **وحدتان باتجاه واحد** `:app → :core`؛ بلا إطار DI، بلا انعكاس، بلا كود ديناميكي.
- **بلا اتصال خدمي**: القواعد داخل التطبيق، والتحديث بتثبيت APK يدويًا.
- **النسخ الاحتياطي معطّل** على كل الإصدارات.
- **بوابة الترخيص قبل التنزيل**: أي مصدر قراره ليس `auto-allowed` ⇒ `NEEDS HUMAN` وخروج بالرمز 2.
- **`STRICT_RESOLVER_IPS` معطّل** حتى قرار الترخيص؛ قائمة العناوين فارغة الآن.
- **`Lockout` مخطط له**: العقد في `:core`، والتنفيذ مؤجّل لموجة لاحقة بلا تغيير على W1–W5.
- **R8 والتصغير مؤجّلان** حتى المرحلة 3.
