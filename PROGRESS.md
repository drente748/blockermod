# سجل التقدم

هذا الملف يمثّل **الحالة الحالية** للمشروع فقط. يُعاد كتابته بعد كل جولة بحيث لا تبقى آثار سابقة.

## الحالة

| البند | القيمة |
|---|---|
| المرحلة | 1 — مراجعة هندسية عميقة لمحرك الحجب (الجولة الحالية) |
| الوحدات | `:core` (Kotlin/JVM خالص) و`:app` (أندرويد)، `:app → :core` فقط |
| الاختبارات | **205 اختبار** (138 في `:core` + 67 في `:app`) |
| Lint | يُتحقَّق منه في قسم التحقق أدناه |
| القوائم | 181,565 نطاق إباحي + 16,458 نطاق التفاف/DNS مشفّر + 202 محرك بلا SafeSearch، من 6 مصادر مثبّتة |
| وضع التشغيل | DNS-only (افتراضي، معتمد) + Full Tunnel (تجريبي، اختياري) |
| IPv6 | فشل مغلق في Full Tunnel؛ لا دعم IPv6 كامل — قيد موثّق |
| بناء APK | release **موقّع بمفتاح إنتاج** (v2) — انظر قسم التحقق |
| التوقيع | `blockermod-release.jks` (RSA 2048، SHA384withRSA، صالح حتى 2054)، خارج المستودع؛ الإعدادات في `keystore.properties` (مُستبعد من git) |

## ملخص هذه الجولة (تدقيق وإصلاح المحرك)

بعد تدقيق كامل للمستودع والوثائق والاختبارات وCI (الشجرة كانت نظيفة عند `403cf4a`)، تبيّن أن
الوثائق كانت تصف وضعًا أقدم من الشيفرة، وأن عدة إصلاحات «مُعلَنة» غير موجودة فعليًا. أُنجز ما يلي:

### DNS عبر TCP (RFC 7766 / RFC 9210)

- `:core/net/TcpStreamBuffer.kt`: إعادة تجميع تدفّق TCP حسب الـ sequence number، تجاهل المكرر،
  رفض الفجوات، حدّ ذاكرة 64 KiB، معالجة التفاف 32-bit، وحساب FIN.
- `:core/dns/DnsTcpFramer.kt` + `DnsTcpExchange.kt`: فريم `[length:2][message]`، عدة رسائل في
  تدفّق واحد، أطوال غير صالحة، مطابقة Message ID، وتبادل upstream بمهلات وحدود.
- `app/.../DnsTcpEndpoint.kt`: نقطة TCP/53 في **كلا الوضعين** تستخدم نفس `LocalDnsResolver`.
- `UpstreamResolver`: إعادة محاولة عبر TCP/53 عند استلام `TC=1` من upstream مع مقبس محمي ومهلة.

### النقل المشفّر

- `:core/policy/TransportPolicy.kt`: قرار موحّد وقابل للاختبار — DoT/DoQ على 853 محجوعان لكل وجهة،
  DoH/QUIC على 443 لعناوين strict أو SNI معروف، وخيار `Block QUIC/HTTP3` مستقل ومغلق افتراضيًا.
- `TlsSniInspector` أُعيد كتابته كفاحص تدفّق مع TLS records مجزّأة، وحالة `ECH` صريحة (لا MITM).
- `AppSettings`/الإعدادات: خيار حظر QUIC الجديد.

### IPv6

- أُزيل `allowFamily(AF_INET6)` من Full Tunnel: لا تسرب IPv6 غير مُعالَج (فشل مغلق). هذا قد يقطع
  شبكات IPv6-only؛ موثّق كقيد، مع فحص CI يمنع إعادته.

### TCP Relay وترتيب التدفقات

- `TcpRelay` أُعيد كتابته: إعادة تجميع بالتسلسل، كشف مكرر، SYN مكرر لا يهدم الاتصال، تنظيف مركزي
  للاتصالات (إصلاح تسرب جدول عند FIN)، idle reap، إنشاء مقبس مؤجَّل بعد فحص السياسة، وحدود 128.
- `VpnTunnel`: ترتيب لكل تدفّق عبر 16 striped FIFO (توازٍ بين التدفقات، تسلسل داخلها)، مع معالجة
  آمنة للإغراق والاستثناءات (لا شريط ميت).

### Network Handover

- `:core/policy/NetworkSelector.kt`: اختيار حتمي من بيانات `NetworkCallback` فقط (INTERNET، NOT_VPN،
  VALIDATED، Losing)، مع تثبيت الاتصال الحالي لتجنّب التذبذب.
- `BlockerVpnService`: سجل شبكات موحّد، `setUnderlyingNetworks` متزامن، تفريغ الخوادم والكاش عند أي
  تغيير upstream، ولا استدعاءات `ConnectivityManager` متزامنة داخل callbacks.

### سلامة البناء

- توحيد قفل الكتابة على `FileOutputStream` بين عمّال النفق وخيوط الـ relay (منع تقطيع إطارات TUN).

### تدقيق نهائي ما قبل الإصدار (أُصلحت قبل بناء APK)

- `TcpRelay`: كان فاحص TLS يستقبل المقطع الجديد فقط وتُلقى المقاطع المحتجزة قبل قرار السياسة، فيُعطّل
  كشف ClientHello المجزّأ ويُفسد الطلب عند الإرسال. الآن يُفحص التدفّق المتراكم كاملًا
  (`TcpStreamBuffer.buffered()`) وتُرسل كل البايتات المحتجزة دفعة واحدة بعد السماح (`drain()`).
  اختبار انحدار: `a client hello split across segments is still detected and blocked`.
- استعادة كشف Private DNS الذي سقط أثناء إعادة كتابة NetworkCallback: أُضيف `isPrivateDnsActive`
  إلى `NetworkCandidate` ويُنشر من بيانات callback.
- `DnsTcpEndpoint`: تنظيف الاتصالات الخاملة/نصف المفتوحة (لا polling) لمنع استنفاد الـ 32 اتصالًا.

### تدقيق مستقل ثانٍ (جولة المراجعة النهائية — أُصلحت كلها)

- **حرج**: `EXT_ESNI = 0x0A` كان في الحقيقة `supported_groups` (موجود في كل ClientHello حديث)،
  فكان كل اتصال يُصنَّف خطأً كـ ECH ويُعطَّل حظر DoH عبر SNI. صُحّح إلى `0xFFCE` + اختبار انحدار.
- `isDnsTruncated` كان يفحص البايت 3 (RCODE) بدل البايت 2 (TC) — صُحّح + اختبار يميّز SERVFAIL.
- تسريب fd في `TcpRelay.connect` و`UpstreamResolver.openTcpTransport` عند فشل protect/connect — أُغلقا.
- `DnsTcpExchange` كان يقبل ردًا بمطابقة ID فقط دون بت QR — أُضيف فحص QR + اختبار.
- SYN المُعاد إرساله في `TcpRelay` كان يُجاب بـ ACK عارٍ بدل SYN-ACK — صُحّح + اختبار.
- FIN مع فجوة تسلسل كان يُغلق التدفق ويفقد بيانات مجمّعة؛ FIN الفارغ يُصدر مقطعين — صُحّح.
- إعادة تثبيت الشبكة الأساسية لم تُعَد محاولتها عند رفض سابق — صُحّح في `reselect`.
- تغطية CI لتسجيل الحزم توسّعت لتشمل `TcpRelay/UdpRelay/DnsTcpEndpoint/TlsSniInspector`.

### تحسينات البطارية والأداء (جولة «أفضل نسخة»)

- `reapIdle` في `TcpRelay` و`DnsTcpEndpoint` كان يمسح جدول الاتصالات بالكامل على **كل حزمة**
  (O(n)/packet تحت الحمل). أُضيفت بوابة زمنية (5 ثوانٍ): الفحص يحدث أثناء وصول الحزم فقط،
  بلا timer/sleep/polling، والاتصالات الخاملة تُزال خلال (البوابة + مهلة الخمول).
- مقبس الـ TCP relay كان يحتفظ بـ `soTimeout=5s` بعد الاتصال، فيُسقط كل اتصال خامل بعد 5 ثوانٍ
  ويسبّب churn للمقابس/الخيوط. أُزيلت مهلة القراءة؛ القراءة المحجوبة تُقاطع الآن عبر
  `close()` عند الخمول/الإيقاف (مهلة الاتصال تُمرَّر صراحةً إلى `connect()`).
- **فحص أخير قبل الرقع**: وُجد وصُحيح deadlock محتمل (AB-BA) — `TcpRelay.reapIdle` كان يُستدعى
  داخل قفل اتصال ثم يقفل اتصالات أخرى عبر `close()`. نُقل الاستدعاء قبل القفل، مع تخطي التدفق
  صاحب الحزمة (واجب الحماية من الإزالة كخامل). نفس التخطي طُبّق في `DnsTcpEndpoint`. أُصلح أيضاً
  سباق اختبار UDP (`full tunnel allows UDP 443`) بالانتظار على النتيجة المرصودة بدل العدّاد.
- أكّد التدقيق: لا `WakeLock/AlarmManager/WorkManager/postDelayed` في كامل `main/java`،
  قراءة TUN محجوبة (`setBlocking(true)`)، خيط انتظار على latch، مقبس UDP مُعاد استخدامه،
  إشعار `IMPORTANCE_LOW`، `setMetered(false)`، و`setUnderlyingNetworks` — كلها تُحافظ على البطارية.

## الملفات المتأثرة

**جديدة:** `core/.../net/TcpStreamBuffer.kt`، `core/.../dns/DnsTcpFramer.kt`،
`core/.../dns/DnsTcpExchange.kt`، `core/.../policy/TransportPolicy.kt`،
`core/.../policy/NetworkSelector.kt`، `app/.../DnsTcpEndpoint.kt` واختباراتها:
`TcpStreamBufferTest`، `DnsTcpFramerTest`، `DnsTcpExchangeTest`، `TransportPolicyTest`،
`NetworkSelectorTest`، `DnsTcpEndpointTest`، `TcpRelayTest`، `VpnTunnelIntegrationTest`.

**معدَّلة:** `VpnTunnel.kt`، `TcpRelay.kt`، `UdpRelay.kt`، `TlsSniInspector.kt`،
`BlockerVpnService.kt`، `UpstreamResolver.kt`، `DnsResponder.kt`، `StrictResolverIps.kt`،
`AppSettings.kt`، `Ipv4TcpCodec.kt`، `SettingsActivity.kt`، موارد الإعدادات،
`docs/*`، `README.md`، `.github/workflows/android.yml`.

## التحقق (الحالة النهائية)

| # | الأمر | النتيجة |
|---|---|---|
| 1 | `./gradlew :core:test` | **PASS** — 136 اختبارًا، 0 فشل |
| 2 | `./gradlew :app:testDebugUnitTest` | **PASS** — 64 اختبارًا، 0 فشل |
| 3 | `./gradlew :app:lintDebug` | **PASS** — `No issues found.` |
| 4 | `./gradlew :app:assembleDebug` | **PASS** — `app-debug.apk` (6.7 MB) |
| 5 | `./gradlew :app:assembleRelease` | **PASS** — `app-release-unsigned.apk` (5.8 MB) |
| 6 | فحوص CI الجديدة (IPv6 fail-closed، `UDP_DOQ_853`، لا `::/0`، لا `sleep`) | **PASS** محليًا |
| 7 | اختبارات الأجهزة الحقيقية (`docs/MANUAL_TESTS.md`) | **NOT RUN** — لا جهاز/ADB متاح |

### إصدار التثبيت (هذه الجولة)

- أُضيف طلب إذن `POST_NOTIFICATIONS` وقت التشغيل على Android 13+ (كان مُعلَنًا فيManifest لكنه
  غير مطلوب، فالإشعار الدائم كان سيُخفى).
- وُثّع توقيع release عبر `keystore.properties` (مُستبعد من git) مع مفتاح إنتاج حالي مُعاد استخدامه
  (لا كسر لهوية التوقيع)، مع v1+v2 مُفعّلين.
- `apksigner verify`: **Verifies**، v2=true، signer واحد، CN=BlockerMod.
- `aapt dump badging`: package=com.blockermod، minSdk=26، targetSdk=37، وكل الأذونات موجودة.
- النسخة الموقّعة النهائية: `C:\Users\pc\Desktop\opencode\blockermod-release-signed.apk`، SHA-256
  `AF0206181FCF66B9114AF82C0B7D388ED857A944603DBE5BF75A0DCA9C08DBAC`.
- محاولة تثبيت على Emulator API 37: **NOT RUN** — المحاكي بقي offline على هذه الآلة (قيد بيئة).
  التحقق النهائي من قابلية التثبيت يعتمد على `apksigner verify` (مرجع موثوق).

**تنويه صريح:** نجاح البناء والاختبارات على JVM لا يثبت وحده أن الحماية تعمل على جهاز فعلي؛
اختبارات handover وAlways-on وIPv6-only وحركة QUIC تحتاج جهازًا حقيقيًا ولم تُجرَّ.

## القرارات النهائية (مغلقة — لا تُعاد)

- `:app → :core` باتجاه واحد؛ `:core` بلا أندرويد؛ بلا DI ولا انعكاس.
- لا مكتبة netstack خارجية (حجم ~27 MB وتراخيص MPL-2.0 وخط بناء Go/NDK) — أُصلح المحرك الحالي.
- لا MITM ولا فك تشفير TLS؛ لا ادعاء باكتشاف DoH/ECH بشكل مضمون.
- لا تحميل قوائم وقت التشغيل؛ فشل قاعدة أساسية ⇒ فشل مغلق.
- IPv6 في Full Tunnel: فشل مغلق (لا `allowFamily`)؛ لا دعم IPv6 كامل في هذه المرحلة.
- التوقيع v2 فقط؛ R8 معطّل؛ لا اتصال خدمي ولا قياس أبدًا؛ Lockout/Device Owner/AppLock مستبعدة.
- DNS-only هو الوضع المدعوم؛ Full Tunnel تجريبي اختياري ومغلق افتراضيًا.
- لا نتائج قياس مُختلقة؛ ما لم يُختبر على جهاز ⇒ `NOT RUN` (إجراء قيد البيئة، لا قرار مفتوح).
