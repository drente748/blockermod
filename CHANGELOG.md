# Changelog

سجل زمني للتغييرات. كل جولة عمل تُسجَّل هنا.

## Unreleased - Initial scaffold

### Added

- هيكل مشروع Gradle بوحدة `app` واحدة: `settings.gradle.kts`، `build.gradle.kts`، `app/build.gradle.kts`، `gradle.properties`، `gradle/libs.versions.toml` (كتالوج الإصدارات)، ومُشغّل Gradle مع تحقّق SHA-256 لتوزيعه.
- سلسلة أدوات حديثة: Android Gradle Plugin `9.5.1`، Gradle `9.9.1`، Kotlin عبر دعم AGP المدمج، `compileSdk/targetSdk 37`، `minSdk 26`، هدف JVM 17.
- `BlockermodApp` كتطبيق Android أساسي.
- عقود النواة في `com.blockermod.core`: `BlockingEngine`، `AppLockManager`، `DeviceOwnerManager`، و`BlockDecision`.
- مضيف المحرك `core.vpn.BlockerVpnService` كنقطة دخول معرَّفة في المانيفست بنوع خدمة أمامية `specialUse` وصلاحية `BIND_VPN_SERVICE` وخاصية subtype.
- أذونات الشبكة والخدمة الأمامية وإشعارات الإصدارات ≥ 33.
- `res/xml/data_extraction_rules.xml` و`res/xml/backup_rules.xml`: تعطيل النسخ الاحتياطي السحابي ونقل البيانات بين الأجهزة على كل الإصدارات.
- توثيق: `README.md` (الفلسفة ونموذج التوزيع)، `ARCHITECTURE.md` (الطبقات والعقود والقرارات المفروضة بسياسات النظام)، `PROGRESS.md` (خريطة المراحل والحالة الحالية)، `CONTRIBUTING.md` (قواعد المساهمة).
- لغة التطبيق بالإنجليزية: الشيفرة والموارد والتسميات والتعليقات داخل `app`.

### Not included (deliberately)

- لا محرك حجب مُنفَّذ: لا نفق VPN، ولا حلّال DNS، ولا مطابقة قواعد.
- لا واجهة مستخدم ولا ثيم ولا أي مورد تصميمي.
- لا قوائم حظر ولا مصدر بيانات خارجي.
- لا إطار DI ولا أي مكتبة اعتماد جديدة.
- لا إنتاج ملف APK.
