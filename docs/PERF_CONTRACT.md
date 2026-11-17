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
- **DNS عبر TCP (RFC 7766/9210)**: إلزامي في كلا الوضعين. `DnsTcpEndpoint` يعيد تجميع التدفق
  حسب sequence number، ويفرّم `[length:2][message]` عبر `DnsTcpFramer` (رسائل مجزّأة/متعددة/
  متزامنة/مكرّرة/خارج الترتيب)، ويطبّق نفس `LocalDnsResolver`.
  - **الذاكرة**: `stream.drain()` بعد كل `feed()` ⇒ حد 64 KiB ينطبق على الرسالة غير المكتملة فقط.
  - **الردود**: `TcpSendQueue` يقسّم الرد إلى مقاطع MSS العميل (≤1460)، يحتفظ غير المؤكَّد، ويعيد
    الإرسال عند 3 ACKs مكررة أو استعلام مُعاد؛ FIN مؤجَّل حتى الإقرار الكامل. بلا مؤقّت RTO.
  - **المصافحة**: يُتحقَّق من ACK=ISN+1 وSEQ=clientISN+1؛ أي ACK خاطئ ⇒ RST.
  - **Upstream**: `DnsTcpExchange` بمهلة مطلقة (nanoTime) ومطابقة ID+QR+Question Section.

## قواعد إضافية لهذه الجولة

| # | القاعدة | آلية الفرض | الملف |
|---|---|---|---|
| R12 | فريم DNS-over-TCP صحيح، مطابقة Message ID، وحدود للرسائل/الذاكرة؛ TC=1 يُعاد عبر TCP مع مهلة | اختبارات وحدة (`DnsTcpFramerTest`, `DnsTcpExchangeTest`, `DnsTcpEndpointTest`) | `core/.../DnsTcpFramer.kt`، `DnsTcpExchange.kt`، `app/.../DnsTcpEndpoint.kt`، `UpstreamResolver.kt` |
| R13 | سياسة نقل موحّدة: DoT/DoQ 853 محجوعان، UDP/443 يُحظر لعناوين DNS معروفة أو بخيار صريح (افتراضيًا مغلق)، ولا ادعاء باكتشاف ECH | اختبارات وحدة + `grep` في CI | `core/.../TransportPolicy.kt`، `app/.../VpnTunnel.kt` |
| R14 | IPv6 فشل مغلق في Full Tunnel: لا `allowFamily(AF_INET6)` ولا مسار IPv6؛ الحزم غير المُعالجة تُسقط | `grep` في CI + اختبار وحدة | `BlockerVpnService.kt`، `VpnTunnelIntegrationTest.kt` |
| R15 | ترتيب لكل تدفّق TCP (striped FIFO) دون إلغاء التوازي بين التدفقات، وتنظيف مركزي للاتصالات الخاملة/المغلقة | اختبارات وحدة | `VpnTunnel.kt`، `TcpRelayTest.kt` |
| R16 | Handover يعتمد فقط على بيانات `NetworkCallback`، ويُفرّغ DNS والكاش القديم عند أي تغيير upstream | اختبار وحدة للسياسة + مراجعة كود (جهاز مطلوب للتحقق الكامل) | `core/.../NetworkSelector.kt`، `BlockerVpnService.kt` |
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
| R1 | مسار IPv6 افتراضي `::/0` (سمة `0.0.0.0/0` مسموحة صراحةً في Full Tunnel التجريبي) |
| IPv6 fails closed | استدعاء `allowFamily(...AF_INET6)` في أي مكان في `app/src/` |
| DoQ classification | غياب تصنيف `UDP_DOQ_853` في `:core` |
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
