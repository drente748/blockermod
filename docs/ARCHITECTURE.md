# بنية BlockerMod

## 1. نظرة عامة

المشروع وحدتا Gradle: **`:core`** (Kotlin/JVM خالص) و**`:app`** (تطبيق أندرويد).

```
:app ──▶ :core
```

الخلاصة المعمارية: `:core` لا يجوز له استيراد أي شيء من منصّة أندرويد — يُفرض ذلك بالمترجم، لا
بالوثيقة، لأن منطق الحجب يجب أن يُختبر ويُطوَّر كوحدة JVM مستقلة.

| الوحدة | النوع | المسؤولية | تعتمد على |
|---|---|---|---|
| `:core` | `kotlin("jvm")`، `jvmToolchain(17)` | عقود الحظر: `BlockingEngine`، `BlockingResult`، `BlockReason`، `BlockingState`، `DomainMatcher`، `SafeSearchTable`، `LockoutPolicy` | لا شيء (مكتبة Kotlin القياسية فقط) |
| `:app` | `com.android.application` | نقطة الدخول، الخدمة الأمامية، النفق، حلّال upstream، ربط engine بالقوائم | `:core` |
| `:app` حزمة `platform.vpn` | داخل `:app` | `BlockerVpnService`، `VpnTunnel`، `DnsResponder`، `UpstreamResolver`، `DnsCache`، `StrictResolverIps` | `:core`، Android SDK |
| `:app` حزمة `platform.deviceowner` | داخل `:app` | عقد الوضع المستقبلي (غير مُفعَّل) | `:core` |
| `:app` حزمة `platform.applock` | داخل `:app` | عقد مستقبلي (غير مُفعَّل) | `:core` |

**قاعدة الاتجاه:** `:app → :core`. لا يستورد `:core` أي شيء من `:app`، ولا تستورد `platform.*`
إلا عقود `:core`.
**قاعدة البناء:** لا إطار DI. البناء يدوي في `:app`، والاختيار يُقرأ من الكود لا من الانعكاس.
**قاعدة الحجم:** وحدة `:core` تستخدم Kotlin JVM بإصدار مطابق لإصدار Kotlin المضمّن داخل إضافة البناء.

## 2. العقود (`:core`)

```kotlin
interface BlockingEngine {
    val state: BlockingState
    fun start()
    fun stop()
    fun evaluate(domain: String): BlockingResult
}

sealed class BlockingResult {
    object Allowed : BlockingResult()
    data class Blocked(val reason: BlockReason) : BlockingResult()
    data class Rewrite(val cnameTarget: String, val original: String) : BlockingResult()
    data class Error(val message: String) : BlockingResult()
}

enum class BlockReason {
    BLOCKLIST_ADULT, BLOCKLIST_BYPASS, BLOCKLIST_UNSUPPORTED_ENGINE,
    CANARY, USER_PAUSED, RECOVERY_MODE,
}

interface DomainMatcher { fun matches(domain: String): Boolean }
interface SafeSearchTable { fun lookup(domain: String): String? }
interface LockoutPolicy { fun isLocked(): Boolean; fun remainingMillis(): Long }
```

`evaluate` هي نقطة القرار الوحيدة. المحرّك نقي تمامًا: لا I/O ولا مقابس ولا `Context`.

## 3. ترتيب السياسة (ثمانية مسارات مرتبة)

1. قفل المستخدم (`LockoutPolicy.isLocked()`) ⇒ `Blocked(USER_PAUSED)`.
2. نطاق الـ canary `use-application-dns.net` ⇒ `Blocked(CANARY)`.
3. جدول SafeSearch (مطابقة HOST exact) ⇒ `Rewrite(target, original)`.
4. القائمة البيضاء (exact + النطاقات الفرعية) ⇒ `Allowed` — تتجاوز القوائم الحظرية فقط.
5. قائمة الإباحية ⇒ `Blocked(BLOCKLIST_ADULT)`.
6. قائمة الالتفاف ⇒ `Blocked(BLOCKLIST_BYPASS)`.
7. قائمة المحركات غير المدعومة ⇒ `Blocked(BLOCKLIST_UNSUPPORTED_ENGINE)`.
8. ما لم يطابق أي مسار ⇒ `Allowed`.

**Fail-safe:** إذا لم تستطع قاعدة مصدر إجابة، يرمي المحرّك استثناءً عند التهيئة، فلا يُنشأ محرك
ناقص ولا يبدأ التطبيق.

## 4. لماذا وضع واحد فقط؟

| الخيار | الحالة | السبب |
|---|---|---|
| **VPN + حلّال DNS محلي** | **معتمد** | يعمل على أي جهاز بلا root، بلا حساب، بلا خادم، وقابل للاختبار وحدةً وحدة |
| root + `iptables` | مستبعد | يتطلب root؛ الحجب يقاوم تحديثات النظام |
| Device Owner / Kiosk | مستبعد كوضع | يتطلب تهيئة الجهاز مسبقاً؛ يناقض "APK مستقل يُثبَّت ويُستخدم فوراً" |
| VPN كامل (TCP/UDP tunnel) | مستبعد كوضع منفصل | تكلفة وأخطاء وازدحام؛ مسار DNS يغطّي المصدر الفعلي |
| فلترة داخل المتصفح فقط | مستبعد | لا تصدّق إلا تطبيقاً واحداً |

كل وضع إضافي يعني مسار كود ثانياً وحالتين طرفيتين وسطح أخطاء مضاعف.

## 5. Routing Model

النفق **DNS فقط**: يلتقط عنوان DNS الافتراضي داخل الجهاز ولا يلتقط أي حركة أخرى.

| العنصر | القيمة |
|---|---|
| عنوان واجهة النفق | `10.111.222.1/32` (عنوان خاص) |
| خادم DNS الافتراضي | `10.111.222.3` |
| المسار | `10.111.222.3/32` فقط |
| `setBlocking` | `true` (القراءة تحجب بلا استهلاك معالج) |
| `setMetered` | `false` |
| `setMtu` | `1500` |

لا يوجد `0.0.0.0/0` ولا `::/0`: بقية حركة الجهاز تبقى على شبكتها العادية، وهذا ما يجعل النفق
خفيفًا على البطارية. المسارات الإضافية الخاصة بـ `STRICT_RESOLVER_IPS` (انظر القسم 13) تُضاف
بـ `/32` أيضًا، وهي **مفعّلة** الآن (12 عنوان حلّال عام).

## 6. DNS Encryption Policy

الموقف من تشفير DNS أثناء تشغيل النفق:

1. **Private DNS (DoT على 853) و DoH (443):** لا يُحظران **عالميًا**. لا يقعان داخل النفق أصلًا
   لأن النفق يلتقط عنوان DNS الافتراضي فقط (القسم 5)، فحركة التشفير تخرج من الجهاز كحركة عادية.
2. **الحظر الصارم (Strict Resolver IPs):** **مفعّل** — تُوجَّه 12 عنوان حلّال عام إلى داخل النفق،
   فيُحظر معها كل منفذ إلا 53 (أي 853 و 443 يُسقطان لتلك العناوين فقط). هذا هو معنى
   «الحظر على عناوين الـ resolvers الموجَّهة»؛ الحلّالات المشفّرة الأخرى (أو Private DNS إلى مضيف
   مخصّص) تبقىOutside النطاق ويُعرض تحذير لها.
3. **هل تُستخدم `DevicePolicyManager.setGlobalPrivateDnsMode()`؟** لا كشرط نجاح. عند وجود Device
   Owner فعلاً يمكن استعمالها كإجراء تكميلي، وهي ليست جزءًا من المسار المعتمد.
4. **الأثر المتبقي:** تطبيق يستخدم DoH على 443 يتجاوز حظر أسماء النطاقات، لأنه لا يستعلم عبر DNS
   الافتراضي أصلاً. الثغرة موثّقة في `docs/MANUAL_TESTS.md` ضمن «حدود معروفة».
5. **ردّ الحظر:** أي استعلام ممنوع يُردّ بعنوان null/block فوري، ولا يُمرَّر بأي حال.

## 7. SafeSearch Rewrite

قرار إعادة الكتابة **نقي** داخل `:core`: المحرّك يعيد `Rewrite(target, original)` فقط، وحلّ الهدف
وتحويله إلى سجلات A/AAAA يحدث في طبقة التطبيق.

| المصدر | المضيف (exact) | الهدف |
|---|---|---|
| S1 — Google | `www.<domain>` لكل نطاق في لقطة `supported_domains` | `forcesafesearch.google.com` |
| S2 — Bing | `www.bing.com`، `edgeservices.bing.com` | `strict.bing.com` |
| S3 — DuckDuckGo | `duckduckgo.com`، `www.duckduckgo.com` | `safe.duckduckgo.com` |
| S4 — Brave | `search.brave.com` | `forcesafe.search.brave.com` |
| S5 — YouTube | `www.youtube.com`، `m.youtube.com`، `youtubei.googleapis.com`، `youtube.googleapis.com`، `www.youtube-nocookie.com` | `restrict.youtube.com` |

- المطابقة **exact** فقط: لا نطاقات فرعية (فـ `mail.google.com` لا يُعاد كتابته).
- جدول SafeSearch مولَّد وقت البناء في `app/src/main/assets/safesearch.json` من
  `tools/build-safesearch.sh`، ولا يُنزَّل شيء وقت التشغيل.
- استعلام من النوع 65 (HTTPS) أو 64 (SVCB) على اسم مُعاد كتابته لا يستطيع حمل CNAME، فيُردّ
  `NOERROR` بلا بيانات (NODATA)؛ التحويل يقع في طبقة التطبيق.
- **Fail-closed:** تعذّر حلّ الهدف ⇒ `SERVFAIL`، ولا يعود الطلب إلى الاسم الأصلي.

## 8. Socket Protection

- أي مقبس DNS يستخدمه التطبيق (DoH/DoT) يجب أن يُربط بالشبكة الفيزيائية **قبل** `connect()`.
- على أندرويد لا يُتاح واصف ملف `DatagramSocket` علنًا، فيُستعمل الربط بالشبكة عبر
  `Network.bindSocket` (المكافئ الحديث لحماية الـ fd) بدل `VpnService.protect(int)`.
- هذا جزء من **عقد `BlockingEngine.start()`**، وليس تفصيلًا اختياريًا.
- نقطة الحقن معزولة في `SocketBinder` لتسهيل التبديل لاحقًا.
- **خوادم upstream تُقرأ من شبكة فيزيائية فقط**: بعد `establish()` يصبح النفق نفسه هو الشبكة
  الافتراضية، وخادم DNS الوحيد المعلن فيه هو العنوان الافتراضي `10.111.222.3`. لذلك يُسجَّل
  `NetworkCallback` على `NetworkRequest` يحمل `NET_CAPABILITY_NOT_VPN`، وتُتجاهل أي شبكة تحمل
  `TRANSPORT_VPN`، ويُسقط العنوان الافتراضي من قائمة `dnsServers` احتياطًا. بدون ذلك يحلّ النفق
  عبر نفسه ويدخل في حلقة لا تنتهي (يُكشف بـ 5.5 في `docs/MANUAL_TESTS.md`).

## 9. Always-On Startup Path

- Always-On VPN قد يبدأ الخدمة عند الإقلاع **دون نشاط مرئي**؛ لذلك `onStartCommand` →
  `startForeground()` يجب أن ينجح بلا Activity.
- قراءة الإعدادات من التخزين المحلي يجب أن تكون متاحة **قبل** `onStartCommand`.
- الحالة الافتراضية عند الإقلاع: `Idle`. لا يُؤسَّس نفق قبل موافقة النظام على VPN.
- `onRevoke` يوقف النفق نظيفًا ويعيده إلى `Idle`، وخيط القراءة يُوقظ بإغلاق مجرى النفق (بلا polling).

## 10. Domain Matcher Abstraction

- `BlockingEngine` يعتمد على **`DomainMatcher`** لا على `Set<String>`.
- التنفيذ في `:core`: `BinarySearchDomainMatcher` (بحث ثنائي على `ByteBuffer` مرتّب حسب العلامات
  المقلوبة) و`InMemoryDomainMatcher` (قوائم صغيرة).
- صيغة الملف المجمَّع: سجلات `[length:2][bytes]`، والاسم مخزَّن معكوسًا ومفصولاً بـ `0x00`.
- المعنى: النطاق المحجوب يغطي نطاقاته الفرعية، والمطابقة على حدود التسميات فقط
  (`notads.example.com` لا يغطيها `ads.example.com`).

## 11. Data Pipeline & License Gate

خط البيانات من المصادر إلى التطبيق كله **وقت البناء**؛ التطبيق لا ينزّل شيئًا:

```
مصدر مثبَّت (commit + SHA-256)
   │  بوابة الترخيص: أي مصدر قراره ليس auto-allowed ⇒ خروج بالرمز 2 قبل أي تنزيل
   ▼
أداة بناء: تطبيع ← إسقاط عناوين IP وغير الصالح ← إزالة التكرار ← إسقاط الأبناء المغطّاة
   ← إزالة المحمية وSafeSearch ← ترتيب حسب العلامات المقلوبة
   ▼
app/src/main/assets/blocklist.bin  (+ blocklist.meta)
   ▼
مطابقة بالبحث الثنائي على البايتات، بلا تحليل عند بدء التشغيل
```

- بوابة الترخيص تُسجَّل في `docs/LICENSE_DECISIONS.md`، وإشعارات الأطراف الثالثة في
  `docs/THIRD_PARTY_NOTICES.md`.
- `:core` لا يقرأ الشبكة إطلاقًا، والاختبارات تقرأ الملف المجمَّع من القرص مباشرة.
- الأصول تحتوي قوائم حظر حقيقية مبنية وقت البناء: `blocklist.bin` (181,565 نطاقًا إباحيًا)،
  `bypass.bin` (16,458 نطاق DNS مشفّر/التفاف)، `unsupported.bin` (202 محرك بلا SafeSearch)،
  مع ملفات `.meta` تحمل العدد والبصمة؛ انظر `docs/THIRD_PARTY_NOTICES.md`.

## 12. Performance Contract

القواعد R1–R11 وآليات فرضها موثّقة في `docs/PERF_CONTRACT.md`، ويُفرض جزء منها آليًا في خط
الأنابيب عبر فحوص `grep`.

## 13. Strict Resolver IPs (مفعّل)

- `StrictResolverIps.STRICT_RESOLVER_IPS_ENABLED = true` — الميزة مفعّلة.
- القائمة تضم 12 عنوان حلّال عام (Google، Cloudflare، Quad9، AdGuard، OpenDNS، CleanBrowsing)
  كعناوين IP حرفية ثابتة؛ لا يُحلَّل أي اسم وقت التشغيل ولا يُتصل بتلك العناوين.
- تُوجَّه تلك العناوين إلى النفق بـ `/32`، ويُسمح لها بمنفذ 53 فقط، وتُسقط 853 (DoT) و443 (DoH)
  قبل فحص منفط DNS (وإلا لكان فحص المنفذ 53 يجعل قاعدة الإسقاط كودًا ميتًا).
- **الحدود:** هذا يوقف DNS المشفّر إلى الحلّالات المعروفة فقط. Private DNS بنظام أندرويد إلى
  مضيف مخصّص، أو DoH إلى عنوان عشوائي، لا يزال يتجاوز الفلتر؛ لذلك يُعرض تحذير في الواجهة عند
  اكتشاف Private DNS (`EngineStatus.publishPrivateDns`). الإيقاف النظامي الكامل يتطلب Device Owner
  (خيار مؤجّل، انظر القسم 15).
- **الأثر على البطارية:** توجيه عناوين إضافية إلى النفق يعني قراءة حزم أكثر؛ مقبول مقابل منع
  تجاوز الحجب.

## 14. Lockout (Planned)

Lockout is a planned feature to prevent the user from stopping the VPN for a
chosen duration. The contract (LockoutPolicy) lives in :core as a pure interface.
The default implementation (NoOpLockoutPolicy) is a no-op. The real implementation
(DataStore, monotonic time, RecoveryCode, BOOT_COMPLETED fallback) is deferred to a
separate future wave. BlockerVpnService and PolicyEngine already accept LockoutPolicy
as a dependency, so enabling it later requires no changes to W1-W5.

**التصميم التفصيلي المؤجَّل** في `docs/LOCKOUT.md`: الاستمرار بعد إعادة التشغيل يعتمد حفظ بداية
القفل ومدته بتوقيت الحائط (لأن `elapsedRealtime()` يُصفَّر عند الإقلاع) بينما تُحسب المدة المتبقية
أثناء الجلسة بالوقت الرتيب، ويُعالَج رجوع الساعة كنية قفل سارية. ومع `onRevoke` أثناء سريان القفل
تُعاد تهيئة النفق فورًا (مرة واحدة بلا حلقة حارّة) ويعتمد الإكمال على Always-on VPN و`START_STICKY`.
وفشل آلية القفل لا يوقف الحجب: يبقى الوضع الافتراضي. لا `AlarmManager` ولا `WorkManager`.

## 15. Device Owner (Optional, Deferred)

هذا خيار **مؤجَّل** موثَّق فقط: لا كود ولا صلاحيات ولا تفعيل في هذه المرحلة.

**ما هو:** Device Owner هو أعلى دور لإدارة الجهاز في أندرويد. يصبح التطبيق «مالكًا» للجهاز
بالمعنى الإداري، فيستطيع فرض سياسات عليه بدل أن يكون مجرد تطبيق مثبَّت.

**لماذا يُستخدم هنا (لو أُنجِز لاحقًا):**

- **منع إيقاف النفق**: المستخدم لا يستطيع تعطيل خدمة VPN من إعدادات النظام، فلا يلتفّ أحد على
  الحجب بإيقاف الخدمة.
- **منع إلغاء التثبيت**: في وضع Device Owner يُمنع إزالة التطبيق، فتبقى الحماية موجودة.
- **Lockdown**: فرض قائمة التطبيقات المسموح بها (قائمة PID لتطبيقات VPN) في سيناريو الأجهزة
  المُدارة أو وضع الفصول الدراسية، بدل الاكتفاء بحجب النطاقات.
- **ضبط Always-on VPN برمجيًا** عبر `DevicePolicyManager.setAlwaysOnVpnPackage()` بدل مطالبة
  المستخدم بالذهاب إلى الإعدادات.

**كيف يُفعَّل (خيارات معروفة):**

- **ADB**: `adb shell dpm set-device-owner <package>/<receiver>` — يتطلّب جهازًا «طازجًا» (بلا حسابات
  مضافة وبلا مستخدمين أُنشئوا)، وإلا فشلت التهيئة.
- **Shizuku / Dhizuku**: تشغيل أمر التهيئة نفسه عبر خدمة shell بصلاحيات shell، إما بجلسة ADB في
  كل مرة، أو بجلسة Shizuku واحدة.

**التكلفة وحدودها:**

- **إعداد أولي**: خطوة يدوية يطلب فيها المستخدم من الجهاز أن يصبح مملوكًا إداريًا لتطبيق
  protection؛ وهذه ليست تجربة يُتوقّعها مستخدم عادي.
- **قد تتطلّب Factory Reset**: تفعيل Device Owner يجب أن يسبق إضافة أي حساب على الجهاز، فتُفقد
  بيانات المستخدم إن أُضيف حساب قبله.
- **لا يعمل على كل الأجهزة**: بعض الشركات تمنع تهيئة Device Owner على أجهزتها، وبعض الإصدارات
  تتطلّب جهازًا غير مهيّأ مسبقًا.
- **تغيير ملكية الجهاز**: بعد التفعيل يصبح التطبيق مسؤولًا عن سياسات الجهاز، وهذا تغيير في
  علاقة المستخدم بالجهاز قد يُعدّ عدائيًا إن فُرض بلا طلب صريح.
- **عمل جديد**: يستلزم `DeviceAdminReceiver` و`DevicePolicyManager` ودورة حياة جديدة وأذونات
  جديدة (مثل `MANAGE_DEVICE_POLICY`)، وكلها غير موجودة اليوم.

**القرار:** مؤجَّل حتى تعمل W1–W5 على جهاز حقيقي وتثبت استقرارها عمليًا. العقد
`platform.deviceowner.DeviceOwnerManager` موجود اليوم كعقد موثَّق غير مُفعَّل، ولا يُنفَّذ منه شيء.
**لا** يُفعَّل lockdown، ولا `setAlwaysOnVpnPackage()`، ولا أي إذن جديد ضمن هذه المرحلة.

## 16. قرارات ثابتة

1. وحدتان باتجاه واحد `:app → :core`.
2. بلا إطار DI، بلا انعكاس على داخليات النظام، بلا تحميل كود ديناميكي.
3. بلا اتصال خدمي: كل بيانات القواعد داخل التطبيق، والتحديث بتثبيت APK يدويًا.
4. النسخ الاحتياطي معطّل على كل الإصدارات.
5. R8 والتصغير مؤجّلان حتى المرحلة 3.

## 17. غير محسوم بعد

- قرار التراخيص لكل مصدر من المصادر المرشحة.
- القراءة من ملف `safesearch.json` داخل التطبيق (الجدول مولَّد لكنه غير موصول بالمحرّك بعد).
- مصير `AppLockManager` و`DeviceOwnerManager` (عقدان موثّقان غير مُفعَّلين).
