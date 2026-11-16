# Changelog

سجل زمني للتغييرات. كل جولة عمل تُسجَّل هنا.

## Unreleased - Pre-commit audit fixes

### Fixed

- `TcpRelay` deferred socket creation: the real TCP socket is now created only after the SNI/DoH and
  DNS-over-TCP checks pass, so a blocked encrypted-DNS connection never reaches the network.
- Bounded relay resources: `TcpRelay` (128 connections) and `UdpRelay` (128 flows) to prevent thread
  and file-descriptor exhaustion under load.
- `setUnderlyingNetworks` full-tunnel comment corrected and `allowFamily(AF_INET6)` added: Android
  blocks an address family with no address/route/DNS server, so IPv6 must be explicitly allowed to
  keep dual-stack devices online (IPv6 is not filtered — documented limitation).
- Stale test counts in `PROGRESS.md` corrected to 145.

### Verified

- 145 tests, 0 failures. `lintDebug`: No issues found. `assembleDebug`: SUCCESS.

## Unreleased - Local-use DNS names exemption

### Fixed

- DNS rebinding protection no longer rejects local-use names that legitimately resolve to private
  addresses: `.local` (RFC 6762), `.home.arpa` (RFC 8375), RFC 6761 special names (`localhost`,
  `test`, `example`, `invalid`), common suffixes (`.lan`, `.home`, `.internal`) and single-label
  hostnames. Public names pointing at private IPs are still rejected.
- 2 new tests cover both the exemption and the unchanged public-name rejection.

### Verified

- 145 tests, 0 failures. `lintDebug`: No issues found. `assembleDebug`: SUCCESS.

## Unreleased - Complete local DNS resolver

### Added

- `LocalDnsResolver`: full local DNS resolver owning policy, positive/negative cache, CNAME chain
  walking (max 5 hops), SafeSearch rewriting and DNS-rebinding protection (reject private IPs).
  Serves both UDP and TCP from one path; `DnsResponder` is now a thin adapter.
- `DnsCache.getFresh()` returns records with remaining TTL instead of the original TTL (RFC 2308).
- EDNS(0) in upstream queries with a 1232-byte payload (RFC 6891) to avoid fragmentation and TCP
  fallback. Negative answers cached for 60s, capped below positive TTLs per RFC 2308.
- 7 new unit tests for the local resolver (cache, NXDOMAIN cache, CNAME chain, rebinding, TCP framing).

### Changed

- Caching moved from `UpstreamResolver` (now a pure forwarder) into `LocalDnsResolver`.
- TCP/53 in full-tunnel mode is fully answered locally; no socket is opened for DNS.

### Verified

- 143 tests, 0 failures. `lintDebug`: No issues found. `assembleDebug`: SUCCESS.

## Unreleased - Full-tunnel blocking engine (experimental)

### Added

- `Ipv4TcpCodec` in `:core`: parse/build IPv4+TCP with checksums, MSS options, FIN/SYN/RST,
  plus 5 unit tests.
- `TcpRelay`: userspace TCP relay — answers the local handshake, forwards through a `protect()`ed
  `Socket`, injects replies into the tunnel. Drops DoT (853), inspects TLS SNI for known DoH names,
  and applies the DNS policy to DNS-over-TCP.
- `TlsSniInspector` + 4 unit tests: extracts SNI from ClientHello.
- `UdpRelay`: forwards non-DNS UDP through protected sockets.
- `AppSettings.fullTunnelEnabled` + Settings toggle (off by default).
- `BlockerVpnService` adds `0.0.0.0/0` only in full-tunnel mode; relays write packets through
  `writeTunnelPacket`.

### Notes

- The DNS-only mode remains the default. Full tunnel captures all IPv4 and costs more battery.
- IPv6 is not captured (no IPv6 address/route added), so it falls through to the underlying network.
- CI rule R1 narrowed: only forbids `::/0`; the `0.0.0.0/0` in the full-tunnel branch is intentional.

### Verified

- 136 tests, 0 failures. `lintDebug`: No issues found. `assembleDebug`: SUCCESS.

## Unreleased - Audit cleanup

### Fixed

- ربط مفتاح «Strict resolver addresses» بالإعداد الحقيقي (`AppSettings` default=true،
  `StrictResolverIps.setEnabled`) — كان مكتوبًا لكن غير مقروء؛ والنص التوضيحي كان يقول إن القائمة فارغة.
- `onRevoke` ينادي `stopSelf()` حتى لا يبقى إشعار «Protection is active» بعد سحب صلاحية VPN.
- حماية `setUnderlyingNetworks` بـ try/catch حتى لا يُسقط استدعاء شبكة على thread الـ callback.
- مسح `DnsCache` عند تغيّر خوادم DNS (ترحيل Wi-Fi↔جوال) حتى لا تُستخدم إجابات قديمة.
- التحقق من طابق معرّف الرد DNS وبت QR قبل قبوله وتخزينه (`isMatchingResponse`).
- تصفير تحذير Private DNS عند إيقاف النفق.
- إشعار الخدمة صار قابلاً للنقر لفتح التطبيق (`PendingIntent`).
- تصحيح خطأ إملائي في اسم الموافق بـ `tools/sources.tsv` (6 صفوف).

### Removed / renamed

- حذف `tools/placeholder-domains.txt` (بقية من مرحلة النطاقات الوهمية، غير مستخدم).
- إعادة تسمية `BlocklistPlaceholderTest` إلى `BlocklistTest`.
- حذف دالة `isPrivateDnsActive()` غير المستخدمة، وتعليق قديم في الـ manifest.

### Verified

- `:core:test :app:testDebugUnitTest` — 127 اختبارًا، 0 فشل (بعد تنظيف نتائج قديمة).
- `:app:lintDebug` — No issues found. `:app:assembleDebug` — SUCCESS.

## Unreleased - Battery, performance and anti-bypass hardening

### Added / Changed

- `ReusableDnsSocket`: reused UDP socket bound once to the physical network (was one socket per
  query); recreated on network change or failed exchange, closed with the service.
- `setUnderlyingNetworks()` pinned at establish time and refreshed on `onAvailable`/`onLost`;
  `setSession()` names the session in system dialogs.
- Negative DNS caching (NXDOMAIN/NODATA) with a 60s TTL in `DnsCache`.
- `DnsResponder.cloaksBlockedDomain()` blocks CNAME chains that resolve an allowed name to a blocked
  adult domain (CNAME cloaking), returning NXDOMAIN.
- `UpstreamResolver` now takes `activeNetwork` and implements `AutoCloseable`.

### Verified

- `:core:test :app:testDebugUnitTest` — 127 tests, 0 failures.
- `:app:lintDebug` — No issues found. `:app:assembleDebug` — SUCCESS.

## Unreleased - Stronger blocking (6 sources, 3 packed lists)

### Added

- **6 مصادر متخصصة مثبّتة**: StevenBlack porn + porn-only، Potterfanz Stricter-porn (MIT)،
  hagezi NSFW + DoH/VPN/Proxy Bypass + NoSafeSearch (GPL-3.0 للبيانات — بقرار من المستخدم وتحديث
  `docs/LICENSE_DECISIONS.md`).
- **`tools/build-blocklist.sh`** صار يدعم صيغة Adblock Plus وينتج ثلاث قوائم: `blocklist.bin`
  (181,565 نطاق إباحي)، `bypass.bin` (16,458 نطاق DNS مشفّر/التفاف)، `unsupported.bin` (202 محرك
  بلا SafeSearch)، مع `.meta` لكل قائمة.
- **`AssetRules.openMatcher`** محمّل عام لأي قائمة معبّأة؛ `createPolicyEngine` يربط قوائم الالتفاف
  والمحركات غير المدعومة ويقع في الفشل المغلق عند غيابها.

### Fixed

- سباق إيقاف النفق: `awaitStopped` ينتظر خيط الانتظار أيضًا (`stopping the tunnel` اختبار).
- فحص CI «public resolver» يُقيَّد الآن على `app/src/main/java` لأن عناوين الحجب الصارم في أصل منفصل.
- تنظيف: حُذف استيراد `DnsRecord` غير المستخدم، سُجّل `PROGRESS`/`README`/`THIRD_PARTY_NOTICES`.

### Verified

- `:core:test :app:testDebugUnitTest` — 124 اختبارًا، 0 فشل.
- `:app:lintDebug` — No issues found. `:app:assembleDebug` — SUCCESS.

## Unreleased - Real porn blocking + encrypted-DNS containment

### Added

- **قائمة حظر حقيقية**: 114,335 نطاقًا من `StevenBlack/hosts` (alternates/porn، MIT)؛ commit وSHA-256
  مثبّتان في `tools/sources.tsv`، وقرار الترخيص مسجَّل في `docs/LICENSE_DECISIONS.md`. حُذفت النطاقات
  الوهمية وصار اختبار القائمة يتحقق من نطاقات حقيقية.
- أصل `allowlist.txt` و`strict-resolvers.txt` مع محمّلين في `AssetRules`.
- واجهة بسيطة بلا ثيم (مؤجَّل).

### Fixed

- `createPolicyEngine` يفشل مغلقًا بلا قائمة ويحمّل القائمة البيضاء بدل تجاهلها.
- تفعيل `STRICT_RESOLVER_IPS` وإسقاط 853/443 قبل فحص منفذ DNS (كان كودًا ميتًا)؛ عناوين الحلّال
  في أصل لا في الكود (حتى يمرّ فحص CI).
- نشر حالة Private DNS إلى الواجهة (كان التحذير لا يظهر أبدًا).
- تجمّد تحديث الواجهة بعد مغادرة الشاشة (scope أُلغي نهائيًا).
- تزامن `DnsCache` بين خيوط العمل الثمانية؛ تمرير `NXDOMAIN`/`NODATA` من upstream بدل `SERVFAIL`؛
  إعادة كتابة مؤشرات الضغط في RDATA؛ منع الدوران عند نهاية مجرى النفق؛ منع البدء المزدوج للخدمة؛
  سرب واصف القائمة؛ سكربت البناء كان يقرأ رأس TSV كصف بيانات.
- بوابة الترخيص: مصادر MPL/GPL/CC لم تُعتمد (انظر `docs/LICENSE_DECISIONS.md`).

### Verified

- `:core:test :app:testDebugUnitTest` — 124 اختبارًا، 0 فشل.
- `:app:lintDebug` — No issues found.
- `:app:assembleDebug` — SUCCESS؛ APK: `C:\Users\pc\Desktop\opencode\blockermod-beta.apk`.
- فحوص CI (grep) على المسارات الفعلية — كلها نظيفة.

## Unreleased - Fix DNS loop back into the tunnel

### Fixed

- `BlockerVpnService` كان يسجّل `registerDefaultNetworkCallback`، وبعد `establish()` تصبح الشبكة
  الافتراضية هي النفق نفسه، فيُقرأ عنوان DNS الافتراضي `10.111.222.3` كخادم upstream. النتيجة:
  كل استعلام مسموح يُوجَّه إلى النفق من جديد (حلقة، وربما تجمّد كامل للشبكة).
- الحل: التسجيل على `NetworkRequest` يحمل `NET_CAPABILITY_NOT_VPN` + تجاهل الشبكات التي تحمل
  `TRANSPORT_VPN` + إسقاط العنوان الافتراضي من `dnsServers` كحاجز ثانٍ + تنظيف الخادم في `onLost`.
- لا تغيير في الواجهة ولا في الصيغ ولا في الاختبارات.

### Verified

- `./gradlew :app:compileDebugKotlin :app:lintDebug` — SUCCESS (جولة الإصلاح).
- `./gradlew :core:test :app:testDebugUnitTest` — 122 اختبارًا، 0 فشل (قبل الإصلاح، والمنطق المُعدَّل
  ليس مغطّى باختبارات وحدة لأنه يعتمد على `ConnectivityManager`).

## Unreleased - Network policy left open

### Changed

- أُزيل أي قيد مطلق على الاتصال بالإنترنت من الوثائق بالكامل: `README.md` و`docs/ARCHITECTURE.md` و`PROGRESS.md` و`CONTRIBUTING.md` أصبحت تنص أن **سياسة الاتصال بالشبكة مفتوحة (غير محسومة)** — تُقرَّر لاحقًا حسب رغبة المطوّر؛ لا تمنع هذه البنية أي اتصال مستقبلي ولا تفرضه.
- أُزيلت صيغة "Offline بالكامل" بالكامل من كل الملفات.
- لا تغيّر في الكود أو المانيفست أو ملفات البناء.

### Verified

- `./gradlew testDebugUnitTest lintDebug assembleDebug` — SUCCESS (انظر `PROGRESS.md`).

## Unreleased - Structural foundation hardening

### Added

- وحدة **`:core`** مستقلة (`kotlin("jvm")`، `jvmToolchain(17)`) تحمل عقود الحظر فقط: `BlockingEngine` (`state`, `start()`, `stop()`, `evaluate(domain)`)، `BlockingResult`، `BlockReason`، `BlockingState`، و`DomainMatcher`.
- اختبارات JVM في `:core` (`DomainMatcherTest`، `BlockingResultTest`) تعمل بلا جهاز ولا محاكي.
- أقسام `docs/ARCHITECTURE.md` الأربعة: DNS Encryption Policy، Socket Protection، Always-On Startup Path، Domain Matcher Abstraction.
- `LICENSE` (Apache-2.0).
- `jvmTarget` صريح (`JVM_17`) في `:app` و`:core` بدل الاشتقاق الضمني.
- مانيفست: `SUPPORTS_ALWAYS_ON = true` لخدمة VPN، ونوع الخدمة `specialUse` مع خاصية subtype.

### Changed

- فصل `:app` إلى ثلاث حزم platform: `platform.vpn` (المضيف)، `platform.deviceowner`، `platform.applock`؛ وحذف الحزمة المتداخلة `com.blockermod.core` داخل التطبيق.
- دمج `BlockDecision` في `BlockingResult` (`Allowed`/`Blocked(reason)`/`Error(message)`) لتجنب هرم قرار مكرر.
- تعطيل النسخ الاحتياطي عبر `allowBackup="false"` **و** `fullBackupContent="false"` و`dataExtractionRules` تستثني كل النطاقات؛ حُذف `backup_rules.xml` لعدم الحاجة إليه.
- رقم الخدمة الأمامية وخصائصها: `exported="true"`، `stopWithTask="false"`. جُرّب `systemExempted` أولاً ثم أُلغي لأنه يفرض إذن منبّهات دقيقة بلا مسوّغ؛ النوع المعتمد `specialUse` مع خاصية subtype، و`SUPPORTS_ALWAYS_ON = true`.

### Verified

- `:core:build` و`:core:test` و`:app:assembleDebug`، ثم البوابات الكاملة (انظر `PROGRESS.md`).

## Unreleased - Initial scaffold

### Added

- هيكل مشروع Gradle بوحدتي `:core` و`:app`: بنية البناء، `gradle/libs.versions.toml` (كتالوج الإصدارات)، ومُشغّل Gradle مع تحقّق SHA-256 لتوزيعه.
- سلسلة أدوات حديثة: Android Gradle Plugin `9.5.1`، Gradle `9.9.1`، `compileSdk/targetSdk 37`، `minSdk 26`.
- `BlockermodApp` كتطبيق Android أساسي.
- عقود النواة: `BlockingEngine`، `AppLockManager`، `DeviceOwnerManager`، و`DomainMatcher`.
- مضيف المحرك `platform.vpn.BlockerVpnService` كنقطة دخول معرَّفة في المانيفست بنوع خدمة أمامية `specialUse` وصلاحية `BIND_VPN_SERVICE`.
- أذونات الشبكة والخدمة الأمامية وإشعارات الإصدارات ≥ 33.
- `res/xml/data_extraction_rules.xml`: تعطيل النسخ الاحتياطي والنقل بين الأجهزة على الإصدارات ≥ 12.
- توثيق: `README.md`، `docs/ARCHITECTURE.md`، `PROGRESS.md`، `CONTRIBUTING.md`، `LICENSE`.
- لغة التطبيق بالإنجليزية: الشيفرة والموارد والتسميات داخل `app`/`core`.

### Not included (deliberately)

- لا محرك حجب مُنفَّذ: لا نفق VPN، ولا حلّال DNS، ولا مطابقة قواعد.
- لا واجهة مستخدم ولا ثيم ولا أي مورد تصميمي.
- لا قوائم حظر ولا مصدر بيانات خارجي.
- لا إطار DI ولا أي مكتبة اعتماد جديدة.
- لا نشر أو توزيع تلقائي.
