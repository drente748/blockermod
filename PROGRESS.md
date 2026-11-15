# سجل التقدم

هذا الملف يمثّل **الحالة الحالية** للمشروع فقط. يُعاد كتابته بعد كل جولة بحيث لا تبقى آثار سابقة.

## الحالة

| البند | القيمة |
|---|---|
| المرحلة الحالية | 0 — الهيكل الأساسي (مكتملة فعلياً) |
| المرحلة التالية | 1 — محرك الحجب (لم تبدأ) |
| واجهة مستخدم | غير موجودة (مؤجّلة حتى يعمل المحرك) |
| البناء | `clean` + `:core:build`/`:core:test` + `assembleDebug/Release` + `lintDebug` — 0 خطأ |

## آخر تعديلات هذه الجولة

- **رفع قيد عدم الاتصال بالإنترنت من الوثائق بالكامل**: أي نص في `README.md` و`ARCHITECTURE.md`
  و`PROGRESS.md` و`CONTRIBUTING.md` يحظر الاتصال بالإنترنت أو يفرض العمل Offline حُوِّل إلى
  **سياسة مفتوحة (غير محسومة)** — تُقرَّر لاحقًا حسب رغبتك.
- **لا تعديل على الكود ولا المانيفست ولا ملفات البناء**.
- **ملاحظة سياقية**: هذا المستودع لا يحتوي أصلاً على أي جزء من "ميزة التحديث" (لا ملفات تحديث،
  لا `AppContainer.kt`، لا مفتاح تحديث في أي ملف، لا `REQUEST_INSTALL_PACKAGES`، لا `.github/`)،
  فتعليمات إزالتها بالكامل لا تُوجد ما يُحذف. بقيت `INTERNET` لأنها مطلوبة لمحرك الحجب نفسه،
  وأذونات الخدمة تبقى لأنها إلزام فحص `lintDebug` على إعلان الـ VpnService.

## ما هو موجود في المشروع فعليًا

- **وحدة `:core` مستقلة** (`kotlin("jvm")` + `jvmToolchain(17)`): عقود الحظر فقط
  (`BlockingEngine` بـ `state`/`start()`/`stop()`/`evaluate(domain)`)، `BlockingResult`
  (`Allowed`/`Blocked(reason)`/`Error(message)`)، `BlockReason`، `BlockingState`، `DomainMatcher`.
  اختبارات JVM في `:core` تعمل بلا جهاز.
- **`:app` منفصلة إلى حزم `platform.*`**: `platform.vpn` (المضيف)، `platform.deviceowner`،
  `platform.applock`. حُذفت `com.blockermod.core` داخل التطبيق بالكامل.
- **الترخيص**: `LICENSE` (Apache-2.0).
- **`jvmTarget` صريح** (`JVM_17`) في `:app` و`:core` بدل الاشتقاق الضمني.
- **النسخ الاحتياطي معطّل كلياً**: `allowBackup="false"` + `fullBackupContent="false"` +
  `dataExtractionRules` تستثني كل النطاقات؛ حُذف `backup_rules.xml` لانتفاء الحاجة.
- **نوع الخدمة الأمامية: `specialUse`** (بعد استبعاد `systemExempted` الذي يشترط في فحص AGP 9.5.1
  إذن منبّهات دقيقة بلا مسوّغ شرعي لهذا التطبيق)، مع خاصية subtype `vpn_blocking_engine`،
  و`SUPPORTS_ALWAYS_ON=true`، و`exported="true"`، و`stopWithTask="false"`.
- **إعدادات Gradle للبيئات المحدودة**: الجهاز 4GB؛ خُفّض heap و`workers.max=1`، وعُطّل `parallel`.
  إضافة `foojay` في `settings.gradle.kts` توفّر JDK 17 تلقائيًا (`jvmToolchain(17)`).
- **`ARCHITECTURE.md`** يشرح: وحدتا البناء والاتجاه، DNS Encryption Policy، Socket Protection،
  Always-On Startup Path، Domain Matcher Abstraction.
- **دمج `BlockDecision` في `BlockingResult`**: لا هرم قرار مكرر؛ `evaluate` يعيد `BlockingResult`.
- **سياسة الاتصال مفتوحة**: لا استدعاءات شبكة في الكود الحالي ولا أي اعتماد يتصل بخدمة؛ أي قرار
  اتصال مستقبلي بيدك، ولا يمنعه هذا البناء ولا يفرضه.

## المرحلة 0 — الهيكل الأساسي [مكتملة]

- [x] وحدتا Gradle: `:core` (Kotlin/JVM خالص، بلا Android) و`:app` (Android)، اتجاه الاعتمادية أحادي: `:app → :core`.
- [x] سلسلة أدوات: Android Gradle Plugin `9.5.1`، Gradle `9.9.1`، `compileSdk/targetSdk 37` (`compileSdkMinor = 0`)، `minSdk 26`، هدف JVM 17.
- [x] كتالوج إصدارات `gradle/libs.versions.toml` (AGP + مكتبات فقط).
- [x] `local.properties` يشير إلى SDK المحلي؛ `.gitignore` يغطي مخرجات البناء و`.kotlin/`.
- [x] `BlockermodApp` + `AndroidManifest.xml` بالخدمة المعلنة ودون أي أذونات تحديث.
- [x] `:core/`: عقود + اختبارات JVM (`DomainMatcherTest`، `BlockingResultTest`).
- [x] توثيق: `README.md`، `ARCHITECTURE.md`، `CHANGELOG.md`، `CONTRIBUTING.md`، `LICENSE`.

**قيد مقصود:** لا ميزة ولا واجهة ولا ثيم، ولا نشر للتوزيع في هذه المرحلة.

## المرحلة 1 — محرك الحجب [لم تبدأ]

- [ ] حلّال DNS داخل `VpnService`: التقاط الاستعلام، تحليل اسم النطاق، الردّ.
- [ ] مطابقة النطاق عبر `DomainMatcher` (تطبيق Trie معكوس على التسميات في المرحلة 1).
- [ ] قائمة قواعد مضمّنة داخل التطبيق (الصيغة والنطاق ومصدر المراجعة).
- [ ] تمرير الاستعلامات المسموحة عبر منفذ محمي بـ `VpnService.protect()`.
- [ ] حظر المنفذ 853 (DoT) داخل النفق افتراضياً، وDoH في المتصفحات موثق كتابع غير معالج.
- [ ] إشعار دائم للخدمة + `onStartCommand`/`onRevoke`/`onDestroy`، ومسار إقلاع Always-On بلا نشاط.
- [ ] استدعاء `VpnService.prepare()` من نشاط مرئي فقط (أول شاشة، آخر خطوة في هذه المرحلة).
- [ ] قياس الأثر: هل يعترض المسار نسبة معقولة من استعلامات النظام؟

## المرحلة 2 — الواجهة [مؤجّلة حتى تكتمل المرحلة 1]

- [ ] شاشة واحدة: تشغيل/إيقاف + حالة المحرك (Material 3، بلا أصول خارجية).

## المرحلة 3 — التوزيع [لم تبدأ]

- [ ] بناء APK موقّع + نسخة release مع R8.
- [ ] تثبيت على جهاز فعلي واختبار Wi-Fi وبيانات الجوال.
- [ ] دليل استخدام داخل التطبيق.

## التحقق الحالي

| # | الأمر | النتيجة |
|---|---|---|
| 1 | `./gradlew clean` | SUCCESS |
| 2 | `./gradlew :core:build :core:test` | SUCCESS — اختبارات JVM تعمل بلا Android |
| 3 | `./gradlew :app:assembleDebug` | SUCCESS |
| 4 | `./gradlew :app:assembleRelease` | SUCCESS |
| 5 | `./gradlew :app:lintDebug` | **0 خطأ**، تحذير وحيد: `MissingApplicationIcon` (الأيقونة مرحلة هوية) |
| 6 | `grep -r "import android" core/src/` | 0 نتائج |
| 7 | `grep -r "specialUse" app/src/` | نتائج موجودة **بالقرار** (بعد استبعاد `systemExempted`) |
| 8 | `grep -r "AccessibilityService\|UsageStatsManager" app/src/` | 0 نتائج |
| 9 | `grep -r "REQUEST_INSTALL_PACKAGES" app/src/` | 0 نتائج |
| 10 | `grep -r "GitHub\|https?://" app/src/` | مساحة أسماء Android الإلزامية فقط |

## قرارات ثابتة

- **سياسة الاتصال بالشبكة مفتوحة (غير محسومة)**: تُقرَّر لاحقًا حسب رغبتك؛ لا يفرض هذا البناء أي قيد
  على أي اتصال مستقبلي ولا يمنعه (لا قياس ولا إحصاء أو تحديثات داخل التطبيق ما لم تقررها أنت لاحقًا).
- **وضع تشغيل واحد**: نفق DNS محلي داخل `VpnService` فقط (لا root ولا Device Owner ولا فلترة متصفح).
- **وحدتان باتجاه واحد** `:app → :core` — انقل لا تنسخ عند أي تحريك.
- **بلا إطار DI**، بلا انعكاس على داخليات النظام، بلا تحميل كود ديناميكي.
- **`BlockingEngine` يعتمد `DomainMatcher`** لا `Set<String>` — التنفيذ اللاحق خلف الواجهة.
- **النسخ الاحتياطي معطّل على كل الإصدارات.**
- **تقسيم Gradle modules أبعد من `:app`/`:core` مؤجّل** حتى تستقر حدود الكود.
- **R8 والتصغير مؤجّلان** حتى المرحلة 3.
