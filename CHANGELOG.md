# Changelog

سجل زمني للتغييرات. كل جولة عمل تُسجَّل هنا.

## Unreleased - Network policy left open

### Changed

- أُزيل أي قيد مطلق على الاتصال بالإنترنت من الوثائق بالكامل: `README.md` و`ARCHITECTURE.md` و`PROGRESS.md` و`CONTRIBUTING.md` أصبحت تنص أن **سياسة الاتصال بالشبكة مفتوحة (غير محسومة)** — تُقرَّر لاحقًا حسب رغبة المطوّر؛ لا تمنع هذه البنية أي اتصال مستقبلي ولا تفرضه.
- أُزيلت صيغة "Offline بالكامل" بالكامل من كل الملفات.
- لا تغيّر في الكود أو المانيفست أو ملفات البناء.

### Verified

- `./gradlew testDebugUnitTest lintDebug assembleDebug` — SUCCESS (انظر `PROGRESS.md`).

## Unreleased - Structural foundation hardening

### Added

- وحدة **`:core`** مستقلة (`kotlin("jvm")`، `jvmToolchain(17)`) تحمل عقود الحظر فقط: `BlockingEngine` (`state`, `start()`, `stop()`, `evaluate(domain)`)، `BlockingResult`، `BlockReason`، `BlockingState`، و`DomainMatcher`.
- اختبارات JVM في `:core` (`DomainMatcherTest`، `BlockingResultTest`) تعمل بلا جهاز ولا محاكي.
- أقسام `ARCHITECTURE.md` الأربعة: DNS Encryption Policy، Socket Protection، Always-On Startup Path، Domain Matcher Abstraction.
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
- توثيق: `README.md`، `ARCHITECTURE.md`، `PROGRESS.md`، `CONTRIBUTING.md`، `LICENSE`.
- لغة التطبيق بالإنجليزية: الشيفرة والموارد والتسميات داخل `app`/`core`.

### Not included (deliberately)

- لا محرك حجب مُنفَّذ: لا نفق VPN، ولا حلّال DNS، ولا مطابقة قواعد.
- لا واجهة مستخدم ولا ثيم ولا أي مورد تصميمي.
- لا قوائم حظر ولا مصدر بيانات خارجي.
- لا إطار DI ولا أي مكتبة اعتماد جديدة.
- لا نشر أو توزيع تلقائي.
