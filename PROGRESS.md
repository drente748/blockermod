# سجل التقدم

هذا الملف يمثّل **الحالة الحالية** للمشروع فقط. يُعاد كتابته بعد كل جولة بحيث لا تبقى آثار سابقة.

## الحالة

| البند | القيمة |
|---|---|
| المرحلة الحالية | 0 — الهيكل الأساسي (مكتملة فعلياً بعد جولة الإصلاحات البنيوية) |
| المرحلة التالية | 1 — محرك الحجب (لم تبدأ) |
| واجهة مستخدم | غير موجودة (مؤجّلة حتى يعمل المحرك) |
| البناء | ناجح: `clean` ← `:core:build/:core:test` ← `assembleDebug/assembleRelease` ← `lintDebug` (0 أخطاء) |

## آخر تعديلات هذه الجولة

- **وحدة `:core` مستقلة** (`kotlin("jvm")` + `jvmToolchain(17)`): تحمل عقود الحظر فقط
  (`BlockingEngine` بـ `state`/`start()`/`stop()`/`evaluate(domain)`)، `BlockingResult`
  (`Allowed`/`Blocked(reason)`/`Error(message)`)، `BlockReason`، `BlockingState`، `DomainMatcher`.
  اختبارات JVM في `:core` تعمل بلا جهاز.
- **`:app` فُصلت إلى حزم `platform.*`**: `platform.vpn` (المضيف)، `platform.deviceowner`،
  `platform.applock`. حُذفت الحزمة المتداخلة `com.blockermod.core` داخل التطبيق بالكامل.
- **الترخيص**: أُضيف `LICENSE` (Apache-2.0).
- **`jvmTarget` صريح** (`JVM_17`) في `:app` و`:core` بدل الاشتقاق الضمني.
- **النسخ الاحتياطي معطّل كلياً**: `allowBackup="false"` + `fullBackupContent="false"` +
  `dataExtractionRules` تستثني كل النطاقات؛ حُذف `backup_rules.xml` لانتفاء الحاجة.
- **نوع الخدمة الأمامية: `specialUse`** (القرار بعد استبعاد `systemExempted` الذي يشترط في فحص
  AGP 9.5.1 إذن منبّهات دقيقة بلا مسوّغ شرعي لهذا التطبيق)، مع خاصية subtype `vpn_blocking_engine`،
  و`SUPPORTS_ALWAYS_ON=true`، و`exported="true"`، و`stopWithTask="false"`.
- **إعدادات Gradle للبيئات المحدودة**: الجهاز 4GB؛ خُفّض `kotlin/java` heap و`workers.max=1`،
  وعُطّل `parallel`. أُضيفت إضافة `foojay` في `settings.gradle.kts` لتوفير JDK 17 تلقائياً
  (`jvmToolchain(17)`) — ظهرت في `~/.gradle/jdks`.
- **`ARCHITECTURE.md`**: أُضيفت الأقسام الأربعة (DNS Encryption Policy، Socket Protection،
  Always-On Startup Path، Domain Matcher Abstraction) وجدول الوحدتين.
- **دمج `BlockDecision` في `BlockingResult`**: لتجنب هرم قرارين متماثلين؛ `evaluate` يعيد
  `BlockingResult` مباشرة.

## المرحلة 0 — الهيكل الأساسي [مكتملة]

- [x] مشروع Gradle بوحدتي `:core` (Kotlin/JVM خالص، بلا Android) و`:app` (Android)، اتجاه الاعتمادية أحادي: `:app → :core`.
- [x] سلسلة أدوات: Android Gradle Plugin `9.5.1`، Gradle `9.9.1`، `compileSdk/targetSdk 37` (`compileSdkMinor = 0`)، `minSdk 26`، هدف JVM 17.
- [x] كتالوج إصدارات `gradle/libs.versions.toml` (AGP + مكتبات فقط).
- [x] `local.properties` يشير إلى SDK المحلي؛ `.gitignore` يغطي مخرجات البناء و`.kotlin/`.
- [x] `BlockermodApp` + `AndroidManifest.xml`: أذونات الشبكة والخدمة الأمامية وإشعارات الإصدارات ≥ 33، وقيود النسخ الاحتياطي الكاملة، ونقطة دخول المحرك `platform.vpn.BlockerVpnService`.
- [x] عقود `:core` + اختبارات JVM (`DomainMatcherTest`، `BlockingResultTest`).
- [x] توثيق: `README.md`، `ARCHITECTURE.md`، `CHANGELOG.md`، `CONTRIBUTING.md`، `LICENSE`.

**قيد مقصود:** لا ميزة ولا واجهة ولا ثيم، ولا نشر للتوزيع في هذه المرحلة.

## المرحلة 1 — محرك الحجب [لم تبدأ]

- [ ] حلّال DNS داخل `VpnService`: التقاط الاستعلام، تحليل اسم النطاق، الردّ.
- [ ] مطابقة النطاق عبر `DomainMatcher` (تطبيق Trie معكوس على التسميات في المرحلة 1).
- [ ] قائمة قواعد مضمّنة داخل التطبيق (الصيغة والنطاق ومصدر المراجعة).
- [ ] تمرير الاستعلامات المسموحة إلى DNS الأصلي عبر منفذ محمي بـ `VpnService.protect()`.
- [ ] حظر المنفذ 853 (DoT) داخل النفق افتراضياً، وDoH في المتصفحات موثق كتابع لا يُعالَج الآن.
- [ ] إشعار دائم للخدمة + `onStartCommand`/`onRevoke`/`onDestroy`، ومسار إقلاع Always-On بلا نشاط.
- [ ] استدعاء `VpnService.prepare()` من نشاط مرئي فقط (أول شاشة، آخر خطوة في هذه المرحلة).
- [ ] قياس الأثر: هل يعترض المسار نسبة معقولة من استعلامات النظام؟

## المرحلة 2 — الواجهة [مؤجّلة حتى تكتمل المرحلة 1]

- [ ] شاشة واحدة: تشغيل/إيقاف + حالة المحرك (Material 3، بلا أصول خارجية).

## المرحلة 3 — التوزيع [لم تبدأ]

- [ ] بناء APK موقّع + نسخة release مع R8.
- [ ] تثبيت على جهاز فعلي واختبار Wi-Fi وبيانات الجوال.
- [ ] دليل استخدام داخل التطبيق (بلا اتصال خدمي).

## التحقق الحالي

| # | الأمر | النتيجة |
|---|---|---|
| 1 | `./gradlew clean` | SUCCESS |
| 2 | `./gradlew :core:build :core:test` | SUCCESS — اختبارات JVM تعمل بلا Android |
| 3 | `./gradlew :app:assembleDebug` و`:app:assembleRelease` | SUCCESS |
| 4 | `./gradlew :app:lintDebug` | **0 خطأ**، تحذير وحيد: `MissingApplicationIcon` (الأيقونة مرحلة هوية) |
| 5 | `grep -r "import android" core/src/` | **0 نتائج** |
| 6 | `grep -r "specialUse" app/src/` | نتائج موجودة **بالقرار**: أُعيد النوع بعد استبعاد `systemExempted` |
| 7 | `grep -r "AccessibilityService\|UsageStatsManager" app/src/` | 0 نتائج |
| 8 | `grep -r "REQUEST_INSTALL_PACKAGES" app/src/` | 0 نتائج |
| 9 | `grep -r "GitHub\|https?://" app/src/` | مساحة أسماء Android الإلزامية فقط |

> ملاحظة تشغيلية: الجهاز 4GB؛ خُفّض heap و`workers=1` لتفادي قتل الـ daemon، و`validateDistributionUrl` وSHA-256 مفعّلان في خصائص الـ wrapper.

## قرارات ثابتة

- **وضع تشغيل واحد**: نفق DNS محلي داخل `VpnService` فقط (لا root ولا Device Owner ولا فلترة متصفح).
- **وحدتان باتجاه واحد** `:app → :core` — انقل لا تنسخ عند أي تحريك.
- **بلا إطار DI**، بلا اتصال خدمي، بلا انعكاس على داخليات النظام، بلا تحميل كود ديناميكي.
- **`BlockingEngine` يعتمد `DomainMatcher`** لا `Set<String>` — التنفيذ اللاحق خلف الواجهة.
- **النسخ الاحتياطي معطّل على كل الإصدارات.**
- **تقسيم Gradle modules أبعد من `:app`/`:core` مؤجّل** حتى تستقر حدود الكود.
- **R8 والتصغير مؤجّلان** حتى المرحلة 3.
