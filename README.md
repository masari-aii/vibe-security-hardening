<div align="center">

# 🛡️ Vibe Security Hardening

**Scan, secure, encrypt, protect and monitor AI-built web apps before launch**

فحص وتأمين وتشفير وحماية ومراقبة المواقع المبنية بالذكاء الاصطناعي قبل الإطلاق

![version](https://img.shields.io/badge/version-3.1.0-111827)
![tests](https://img.shields.io/badge/tests-33%2F33-16a34a)
![benchmark](https://img.shields.io/badge/benchmark-40%2F40%20detected%2C%200%20false%20positives-16a34a)
![controls](https://img.shields.io/badge/controls-27%20%2B%2070%20module%20items-2563eb)
![encryption](https://img.shields.io/badge/encryption-XChaCha20%20%7C%20AES--256--GCM-7c3aed)
![PDPL](https://img.shields.io/badge/Saudi-PDPL%20%7C%20NCA%20ECC-15803d)
![models](https://img.shields.io/badge/models-any%20LLM-0ea5e9)
![license](https://img.shields.io/badge/license-MIT-64748b)

[العربية](#العربية) · [English](#english) · [Screenshots](#screenshots-demo-project) · [Changelog](CHANGELOG.md)

</div>

---

<div dir="rtl">

## العربية

### ما هي؟

كثير من المواقع المبنية بالـ vibe coding تعمل جيدًا لكنها تُطلق بثغرات شائعة: مفاتيح API ظاهرة في المتصفح، قاعدة بيانات مفتوحة، صفحات أدمن بلا حماية، مستخدم يرى بيانات مستخدم آخر، وبيانات حساسة مخزّنة بدون تشفير. هذه المهارة تعطي أي نموذج ذكاء اصطناعي منهجًا ثابتًا وأدوات حقيقية مختبرة:

1. **الكشف**: يتعرّف على التقنيات ويختار دليل الإصلاح المناسب، ويبني خريطة البيانات الحساسة.
2. **التدقيق**: يشغّل الفاحص الآلي واختبارات الصلاحيات، ثم يمرّ على البنود الـ27 والوحدات الإضافية، ولكل بند دليل (الملف ورقم السطر).
3. **الخطة**: يرتّب المشاكل حسب الخطورة.
4. **الإصلاح**: إصلاحات آمنة تلقائية للأمور الآلية، ثم أصغر تعديل ممكن لكل مشكلة مع التشفير وطبقات الحماية.
5. **التحقق**: يعيد الفحص والاختبارات حتى لا تبقى مشكلة حرجة أو عالية.
6. **التقرير**: تقرير احترافي للعميل بشعارك (عربي أو إنجليزي، PDF) فيه درجة الأمان ومقارنة قبل وبعد.

### مخطط سير العمل

<p align="center"><img src="docs/images/workflow-ar.png" alt="مخطط سير عمل المهارة" width="720"></p>

**كيف تقرأ المخطط:** كل بطاقة خطوة، واللون يميز نوعها، والسهم يوضح الترتيب. الشارة الخضراء (↺ 2–6) تعني أن الخطوات من الفحص حتى التحقق تتكرر حتى لا تبقى مشكلة حرجة أو عالية.

| الخطوة | ماذا يحدث | الأداة |
|---|---|---|
| 1. الكشف | يتعرّف على التقنيات (الإطار، قاعدة البيانات، المصادقة، الاستضافة) ويحصر الحقول الحساسة | قراءة ملفات المشروع |
| 2. الفحص | فحص آلي للكود وتاريخ Git والمكتبات والبنية التحتية والموقع المباشر، واختبار الصلاحيات | `scan.py` و `authz_test.py` |
| 3. التدقيق | مراجعة البنود الـ27 والوحدات (E التشفير، P الحماية، D التنبيهات، I البنية، A الذكاء الاصطناعي، K حماية البيانات، N الهيئة الوطنية)، ولكل بند دليل | المهارة + المراجع |
| 4. الخطة | ترتيب المشاكل: حرج ثم عالٍ ثم متوسط ثم منخفض | — |
| 5. الإصلاح | إصلاحات آمنة تلقائية، ثم أصغر تعديل لكل مشكلة، والتشفير وطبقات الحماية | `scan.py --fix` |
| 6. التحقق | إعادة الفحص والاختبارات، وتفعيل الفحص التلقائي عند كل رفع | `scan.py` + GitHub Actions |
| 7. التقرير | تقرير للعميل بالدرجة والمقارنة | `report.py` |
| 8. المراقبة | حجب الهجمات وإرسال التنبيهات، ولوحة وملخص يومي | `guard` + `alerts_dashboard.py` |

### لقطات من الفحص (مشروع تجريبي)

> اللقطات من مشروع متجر تجريبي فيه ثغرات زرعناها عمدًا، ثم نسخة بعد الإصلاح. أرقام لوحة التنبيهات بيانات تجريبية.

#### 1) الفاحص الآلي قبل الإصلاح

<p align="center"><img src="docs/images/term-scan.png" alt="نتيجة الفاحص قبل الإصلاح" width="900"></p>

**كيف تقرأها:** سطر `summary` يعطي عدد المشاكل حسب الخطورة (هنا 11 حرجة و22 عالية). كل سطر بعده مشكلة واحدة: **الخطورة** باللون (أحمر حرج، برتقالي عالٍ، أصفر متوسط، أزرق منخفض)، ثم **رمز البند** (مثل `C24` = مفتاح مسرّب في تاريخ Git، `I5` = إعدادات سحابية)، ثم **الوصف**، ثم **الموقع** بعد `@` (الملف:السطر أو رقم الـ commit)، ثم **الإجراء** بعد `—`. المفاتيح تظهر بآخر 4 أحرف فقط (`…K6J0`) حتى لا تتسرب في التقرير نفسه.

#### 2) الفاحص بعد الإصلاح

<p align="center"><img src="docs/images/term-scan-after.png" alt="نتيجة الفاحص بعد الإصلاح" width="900"></p>

بقيت مشكلتان فقط: متوسطة (`innerHTML`) ومنخفضة (إظهار إصدار nginx)، وصفر حرج أو عالٍ.

#### 3) اختبارات الصلاحيات

<p align="center"><img src="docs/images/term-authz.png" alt="نتيجة اختبارات الصلاحيات" width="900"></p>

**كيف تقرأها:** كل سطر يجرّب صفحة بصفة مستخدم معيّن. `PASS` يعني أن المستخدم مُنع كما يجب (401 أو 403 أو 404). `FAIL` يعني أنه دخل ولم يكن يجب: مثلًا `bob -> 200` على طلب Alice هو ثغرة IDOR، و `alice -> 200` على قائمة المستخدمين هو خلل في صلاحيات الأدمن، و `anonymous -> 200` يعني صفحة محمية تُفتح بدون تسجيل دخول.

#### 4) تقرير العميل قبل وبعد الإصلاح

<table><tr>
<td width="50%"><img src="docs/images/report-before-ar.png" alt="التقرير قبل الإصلاح"><p align="center">قبل الإصلاح: الدرجة 1 من 100</p></td>
<td width="50%"><img src="docs/images/report-ar.png" alt="التقرير بعد الإصلاح"><p align="center">بعد الإصلاح: الدرجة 95 من 100</p></td>
</tr></table>

**كيف تقرأ التقرير:**
- **الدائرة:** درجة الأمان من 100. أخضر 75 فأعلى، أصفر 50 إلى 74، أحمر أقل من 50. وجود أي مشكلة حرجة يحدّ الدرجة عند 59 مهما كانت بقية النتائج.
- **التقدير:** A من 90، B من 75، C من 60، D من 40، وأقل من ذلك F.
- **البطاقات الأربع:** عدد المشاكل حسب الخطورة. الخط الملون على الجانب يطابق لون الخطورة.
- **قبل وبعد الإصلاح:** الدرجة السابقة ← الحالية، ثم **تم حلها** (أخضر)، و**جديدة** ظهرت بعد التعديل (أحمر)، و**ما زالت مفتوحة**. في المثال حُلّت 42 مشكلة ولم تظهر أي مشكلة جديدة.
- **جدول النتائج:** الخطورة، رمز البند، المجال (البنود الأساسية، التشفير، البنية التحتية...)، المشكلة، الموقع، والإجراء المطلوب.
- **الخطوات الموصى بها** و**النطاق والمنهجية** في الأسفل.

نماذج PDF كاملة: [`docs/sample-report-ar.pdf`](docs/sample-report-ar.pdf) · [`docs/sample-report-en.pdf`](docs/sample-report-en.pdf)

#### 5) لوحة تنبيهات الاختراق

<p align="center"><img src="docs/images/dash-ar.png" alt="لوحة تنبيهات الاختراق" width="900"></p>

**كيف تقرأ اللوحة:**
- **البطاقات العلوية:** إجمالي محاولات الهجوم في الفترة، وعدد عناوين IP المختلفة، وعدد أنواع الهجمات.
- **حسب نوع الهجوم:** طول الشريط نسبة إلى أكثر نوع تكرارًا، والرقم بجانبه هو العدد الفعلي. في المثال أكثرها محاولات الوصول لملفات حساسة مثل `.env`.
- **حسب الدولة** و**أكثر العناوين هجومًا:** من أين تأتي الهجمات. العناوين المتكررة مرشحة للحجب في جدار الحماية (WAF).
- **أكثر الصفحات استهدافًا:** ما يحاول المهاجمون الوصول له، ويساعدك في معرفة ما تحميه أولًا.
- **المحاولات يوميًا:** عمود لكل يوم، والرقم فوقه عدد المحاولات، والتاريخ تحته (شهر-يوم). القفزة المفاجئة (مثل 23 و30 محاولة يومي 22 و23) تعني حملة هجوم تستحق المراجعة.
- **آخر الأحداث:** تفاصيل آخر 50 محاولة: الوقت، النوع، IP، الموقع التقريبي، والصفحة.

### قائمة المميزات الكاملة

**الفحص والاختبار**
- فاحص آلي بدون تثبيت (Python 3.8+) يكتشف 40 نوعًا من المشاكل في الكود وتاريخ Git والمكتبات والبنية التحتية والموقع المباشر.
- كشف المفاتيح المسرّبة: AWS و Stripe و OpenAI و Anthropic و GitHub و Google و Slack و SendGrid و Twilio والمفاتيح الخاصة ومفتاح Supabase الخدمي وروابط قواعد البيانات بكلمات مرور، مع إخفاء القيم.
- فحص البنية التحتية: Dockerfile و docker-compose و nginx/Apache و Kubernetes و Terraform و GitHub Actions.
- فحص الموقع المباشر: HTTPS و HSTS والهيدرز والكوكيز و CORS وإظهار الإصدارات والملفات المكشوفة ووثائق الـ API.
- فحص المكتبات المصابة: npm audit و pip-audit و composer audit.
- فحص عميق اختياري بدمج Semgrep و Gitleaks و Trivy.
- اختبارات الصلاحيات (IDOR وصلاحيات الأدمن والوصول بدون تسجيل دخول)، محلية افتراضيًا.
- كتم إنذار خاطئ بعد مراجعته بتعليق `vibe-scan: ignore`.

**الإصلاح**
- إصلاح آمن تلقائي (`--fix`) لا يعدّل الكود ولا يحذف، ويمكن تكراره.
- أدلة إصلاح جاهزة لـ Next.js و Supabase و Firebase و Vercel و Laravel و Django و Express و PHP/WordPress والجوال.
- 27 بندًا أساسيًا لكل منها اختبار تحقق.

**التشفير والحماية**
- خريطة بيانات حساسة تُشفَّر تلقائيًا: الهوية، الجوال، الآيبان، المستندات، التوكنات، المحادثات.
- XChaCha20-Poly1305 (أو AES-256-GCM) مع مفتاح مستقل لكل حقل وربط البيانات بسجلها وفهرس بحث آمن.
- كلمات مرور Argon2id مع pepper، وتشفير الملفات والنسخ الاحتياطية، وإدارة المفاتيح وتدويرها.
- طبقات حماية: جدار حماية CDN/WAF، تحدي البوتات، MFA للأدمن، منع كلمات المرور المسرّبة، زر طوارئ.

**المراقبة والتنبيهات**
- حجب الهجمات (حقن SQL، XSS، تجاوز المسارات، حقن الأوامر، SSRF، محاولات الوصول لـ `.env` و `.git`، تخمين كلمات المرور، بيانات الفخ).
- تنبيه فيه نوع الهجوم و IP والموقع التقريبي والصفحة، عبر الإيميل و Webhook (Slack و Discord و Teams و n8n) وتيليجرام، وواتساب عبر n8n.
- لوحة تنبيهات بالعربي والإنجليزي، وملخص يومي بالإيميل، ووضع مراقبة بدون حجب للأيام الأولى.

**التقارير والامتثال**
- تقرير عميل بشعارك (HTML و PDF، عربي أو إنجليزي) بدرجة أمان ومقارنة قبل وبعد.
- أمان تطبيقات الذكاء الاصطناعي حسب OWASP GenAI LLM Top 10 2026.
- نظام حماية البيانات الشخصية السعودي (K1–K12)، وربط الأدلة بضوابط الهيئة الوطنية للأمن السيبراني (ECC-2:2024) وإطار ساما.

**الجودة**
- 33 اختبارًا آليًا و مقياس دقة: 40 من 40 مشكلة مكتشفة، وصفر إنذار خاطئ.
- يعمل مع Claude وأي نموذج آخر، وملف واحد شامل للصق في أي محادثة.

### الجديد في الإصدار 3

| الميزة | ماذا تفعل |
|---|---|
| 📄 تقرير العملاء | `scripts/report.py`: تقرير HTML و PDF بشعار شركتك وألوانها، عربي أو إنجليزي، درجة أمان من 100 وتقدير (A–F)، مقارنة قبل وبعد الإصلاح (ما حُلّ، ما استجد، ما بقي)، جدول النتائج مربوط بالبنود، وخطوات موصى بها |
| 🔐 اختبارات الصلاحيات | `scripts/authz_test.py`: يثبت أن المستخدم (أ) لا يصل لبيانات المستخدم (ب)، وأن المستخدم العادي لا يدخل صفحات الأدمن، وأن الصفحات المحمية لا تُفتح بدون تسجيل دخول. يعمل محليًا افتراضيًا، والتوكنات من متغيرات البيئة |
| 🏗️ فحص البنية التحتية | Dockerfile و docker-compose و nginx/Apache و Kubernetes و Terraform و GitHub Actions: حاويات بصلاحية root، منفذ قاعدة بيانات مفتوح للإنترنت، مجلدات مكشوفة، TLS قديم، صلاحيات سحابية مفتوحة، ثغرات حقن في ملفات CI |
| 🔧 إصلاح آمن تلقائي | `--fix`: يضيف `.env` لـ `.gitignore`، ينشئ `.env.example` بالأسماء فقط، ويكتب ملفات للمراجعة (سكربت إزالة الملفات الحساسة من Git، مسودة RLS، security.txt، الهيدرز). لا يعدّل الكود ولا يحذف شيئًا |
| 🔬 فحص عميق | `--deep`: يدمج نتائج Semgrep و Gitleaks و Trivy إذا كانت مثبتة |
| 📊 لوحة التنبيهات | `scripts/alerts_dashboard.py`: لوحة لمحاولات الاختراق (الأنواع، الدول، أكثر العناوين هجومًا، يوميًا، آخر الأحداث) مع ملخص يومي بالإيميل |
| 📣 قنوات تنبيه جديدة | إيميل + Webhook (Slack و Discord و Teams و n8n) + تيليجرام + سجل JSONL. واتساب عبر n8n أو مزوّد WhatsApp Business |
| 🇸🇦 الهيئة الوطنية للأمن السيبراني وساما | وحدة تربط أدلة المهارة بمجالات ضوابط NCA ECC-2:2024 الأربعة وإطار ساما للأمن السيبراني |
| ✅ اختبارات ومقياس دقة | `tests/run_tests.py`: ‏33 اختبارًا، يكتشف 40 من 40 ثغرة متعمدة، وصفر إنذار خاطئ على المشروع السليم. يعمل تلقائيًا في GitHub Actions |

### كل ما تغطيه المهارة

| الطبقة | المحتوى |
|---|---|
| الفاحص الآلي | المفاتيح المسرّبة (في الملفات وتاريخ Git)، الملفات الحساسة المرفوعة، المتغيرات السرية الظاهرة للمتصفح، الكود الخطر، الجداول بدون RLS، المكتبات المصابة، البنية التحتية، والموقع المباشر (الهيدرز، الكوكيز، CORS، HTTPS، المسارات المكشوفة) |
| 27 بندًا أساسيًا | الدخول، المفاتيح، قاعدة البيانات، المدخلات، النقل، الهيدرز، منع الإساءة، المكتبات، المراجعة |
| التشفير E1–E9 | خريطة بيانات حساسة تُشفَّر تلقائيًا، XChaCha20-Poly1305 أو AES-256-GCM، مفتاح مستقل لكل حقل، فهرس بحث آمن، Argon2id مع pepper، تشفير الملفات والنسخ الاحتياطية، إدارة المفاتيح وتدويرها |
| الحماية P1–P7 | جدار حماية CDN/WAF، تحدي البوتات، MFA للأدمن، منع كلمات المرور المسرّبة، نسخ احتياطي مُختبر، زر طوارئ |
| كشف الاختراق D1–D9 | يحجب الهجوم ويرسل نوعه وعنوان IP والموقع التقريبي والصفحة المستهدفة، مع لوحة وملخص يومي |
| البنية التحتية I1–I6 | الحاويات، compose، خادم الويب، Kubernetes، السحابة و Terraform، CI/CD |
| اختبارات الصلاحيات Z | IDOR، صلاحيات الأدمن، الوصول بدون تسجيل دخول |
| أمان الذكاء الاصطناعي A1–A11 | حسب OWASP GenAI LLM Top 10 2026 |
| أدلة حسب التقنية | Next.js و Supabase و Firebase و Vercel و Laravel و Django و Express و PHP/WordPress والجوال |
| حماية البيانات الشخصية K1–K12 | الموافقة، سياسة الخصوصية بالعربي، حقوق صاحب البيانات، إبلاغ سدايا خلال 72 ساعة، نقل البيانات خارج المملكة |
| NCA ECC و ساما N | ربط الأدلة بالمجالات، وتحديد الضوابط التنظيمية خارج نطاق الكود |

### التركيب

**Claude (الويب / سطح المكتب / الجوال)**
1. نزّل [`dist/vibe-security-hardening.zip`](dist/vibe-security-hardening.zip).
2. افتح **Customize > Skills** ثم **+** ثم **Upload a skill** واختر الملف. إن كانت عندك نسخة قديمة: افتح المهارة ثم **⋯ > Upload new version**.
3. فعّل المهارة.

**Claude Code**
```bash
git clone https://github.com/masari-aii/vibe-security-hardening ~/.claude/skills/vibe-security-hardening
```

**أي نموذج آخر (ChatGPT و Gemini و DeepSeek و Qwen و Llama...)**: الصق محتوى [`ALL-IN-ONE.md`](ALL-IN-ONE.md) كتعليمات النظام أو أول رسالة.

**وكلاء البرمجة (Cursor و Windsurf وغيرها)**: انسخ مجلد المستودع داخل المشروع وأشر إليه في قواعد المشروع.

### الاستخدام مع النموذج

```text
أمّن وشفّر واحمِ مشروعي: طبّق المهارة كاملة وأعطني تقرير العميل بالعربي.
التقنيات: Next.js + Supabase + Vercel
```
```text
افحص مشروعي فقط بدون تعديل، وأعطني التقرير.
```
```text
اختبر الصلاحيات: هل يستطيع مستخدم رؤية طلبات مستخدم آخر؟
```

### استخدام الأدوات مباشرة (Python 3.8+، بدون تثبيت)

```bash
# 1) فحص كامل وحفظ نقطة البداية
python3 scripts/scan.py ./my-app --url https://my-site.com --json before.json

# 2) إصلاحات آمنة تلقائية (لا تعدّل الكود)
python3 scripts/scan.py ./my-app --fix

# 3) اختبارات الصلاحيات على نسخة محلية
ALICE_TOKEN=... BOB_TOKEN=... ADMIN_TOKEN=... python3 scripts/authz_test.py authz.json --json authz-out.json

# 4) بعد الإصلاح: إعادة الفحص ثم تقرير العميل
python3 scripts/scan.py ./my-app --json after.json
python3 scripts/report.py after.json --baseline before.json --authz authz-out.json \
  --project "موقع العميل" --brand "Masari AI" --logo logo.png --lang ar --pdf

# 5) لوحة تنبيهات الاختراق والملخص اليومي
python3 scripts/alerts_dashboard.py alerts.jsonl --out dashboard.html --brand "Masari AI"
python3 scripts/alerts_dashboard.py alerts.jsonl --digest --send
```

**تفعيل الفحص التلقائي عند كل رفع:** انسخ [`templates/security-scan.yml`](templates/security-scan.yml) إلى `.github/workflows/` في مشروعك، و `scripts/scan.py` إلى `.security/scan.py`.

**تفعيل تنبيهات الاختراق:** انسخ `scripts/guard.mjs` (Node.js) أو `scripts/guard.py` (Python) إلى مشروعك، وحدد القنوات بمتغيرات البيئة: `ALERT_TO` للإيميل، `ALERT_WEBHOOK_URL` لـ Slack و Discord و n8n، `TELEGRAM_BOT_TOKEN` و `TELEGRAM_CHAT_ID` لتيليجرام، `ALERT_LOG_FILE` للوحة. التفاصيل في [`references/intrusion-alerts.md`](references/intrusion-alerts.md).

### تنبيهات مهمة

> الأدوات تفحص فقط الأنظمة التي تملكها أو المصرّح لك باختبارها. اختبار الصلاحيات يعمل محليًا افتراضيًا.

> الموقع الجغرافي في التنبيهات تقريبي (حسب IP)، والمهاجم قد يستخدم VPN.

> وحدتا حماية البيانات الشخصية و NCA قوائم تقنية تساعدك على الامتثال، وليست استشارة قانونية.

> النتيجة تقوية قوية للموقع، لكنها ليست ضمانًا ولا بديلًا عن اختبار اختراق احترافي للأنظمة الحساسة.

</div>

---

## English

### What it is

A skill plus tested tools that turn any LLM into a security reviewer for your own project: it detects the stack, runs an automated scanner and authorization tests, audits 27 core controls plus encryption, protection, intrusion alerts, infrastructure, AI security and Saudi compliance modules, applies safe fixes and minimal diffs, verifies them, and produces a branded client report.

### Workflow diagram

<p align="center"><img src="docs/images/workflow-en.png" alt="Skill workflow diagram" width="720"></p>

**How to read it:** each card is one step; color marks the step type; arrows show the order. The green badge (↺ 2–6) means steps 2 to 6 repeat until no critical or high issue remains.

| Step | What happens | Tool |
|---|---|---|
| 1. Detect | Identify framework, database, auth, hosting; list sensitive fields | Project files |
| 2. Scan | Code, git history, dependencies, infrastructure, live site; authorization tests | `scan.py`, `authz_test.py` |
| 3. Audit | 27 controls + modules (E encryption, P protection, D alerts, I infrastructure, A AI, K PDPL, N NCA), each with evidence | Skill + references |
| 4. Plan | Order by severity: critical › high › medium › low | — |
| 5. Fix | Safe automatic fixes, then minimal diffs; encryption and protection layers | `scan.py --fix` |
| 6. Verify | Re-scan and re-test; enable the scan on every push | `scan.py` + GitHub Actions |
| 7. Report | Client report with score and comparison | `report.py` |
| 8. Monitor | Block attacks, send alerts, dashboard and daily digest | `guard` + `alerts_dashboard.py` |

### Screenshots (demo project)

> Taken from a demo store with deliberately planted issues, then the fixed version. Dashboard numbers are demo data.

**Scanner before fixes** — `summary` gives counts by severity; each line is one finding: severity (color), control ID (e.g. `C24` = secret in git history, `I5` = cloud config), title, location after `@` (file:line or commit), action after `—`. Secrets are shown by their last 4 characters only.

<p align="center"><img src="docs/images/term-scan.png" alt="Scanner output before fixes" width="900"></p>

**Scanner after fixes** — 0 critical, 0 high; one medium and one low remain.

<p align="center"><img src="docs/images/term-scan-after.png" alt="Scanner output after fixes" width="900"></p>

**Authorization tests** — `PASS` = the user was correctly refused (401/403/404). `FAIL` = access that should have been denied: `bob -> 200` on Alice's order is IDOR; `alice -> 200` on the admin user list is a broken role check; `anonymous -> 200` is a protected route open without login.

<p align="center"><img src="docs/images/term-authz.png" alt="Authorization test output" width="900"></p>

**Client report, before and after**

<table><tr>
<td width="50%"><img src="docs/images/report-before-en.png" alt="Report before fixes"><p align="center">Before: score 1/100</p></td>
<td width="50%"><img src="docs/images/report-en.png" alt="Report after fixes"><p align="center">After: score 95/100</p></td>
</tr></table>

How to read it:
- **Gauge:** security score out of 100 (green ≥ 75, yellow 50–74, red < 50). Any critical finding caps the score at 59.
- **Grade:** A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, otherwise F.
- **Four tiles:** findings per severity; the colored edge matches the severity color.
- **Before vs after:** previous score → current score, **Resolved** (green), **New** since the last scan (red), **Still open**. In the demo 42 issues were resolved and none were introduced.
- **Findings table:** severity, control ID, area (core, encryption, infrastructure...), issue, location, required action. Then next steps and scope.

Full PDF samples: [`docs/sample-report-en.pdf`](docs/sample-report-en.pdf) · [`docs/sample-report-ar.pdf`](docs/sample-report-ar.pdf)

**Intrusion alerts dashboard**

<p align="center"><img src="docs/images/dash-en.png" alt="Intrusion alerts dashboard" width="900"></p>

How to read it:
- **Top tiles:** total attack attempts in the period, unique IPs, attack types.
- **By attack type / by country / top attacking IPs / most targeted paths:** bar length is relative to the largest value; the number is the real count. Repeat IPs are candidates for a WAF block; targeted paths show what to protect first.
- **Attempts per day:** one bar per day, count above, date below (MM-DD). A sudden spike (23 and 30 on 11-22 and 11-23) signals a campaign worth reviewing.
- **Latest events:** the last 50 attempts with time, type, IP, approximate location and path.

### Full feature list

- **Scanning & testing:** zero-install scanner (40 issue types) across code, git history, dependencies, infrastructure and the live site; secret detection for AWS, Stripe, OpenAI, Anthropic, GitHub, Google, Slack, SendGrid, Twilio, private keys, Supabase service-role keys and DB URLs (masked); Docker, compose, nginx/Apache, Kubernetes, Terraform and GitHub Actions checks; live HTTPS/HSTS/headers/cookies/CORS/exposed-path checks; npm/pip/composer audits; optional Semgrep, Gitleaks and Trivy; IDOR/admin/unauthenticated authorization tests (local by default); inline `vibe-scan: ignore` for reviewed false positives.
- **Fixing:** safe idempotent `--fix` that never edits code; stack playbooks for Next.js, Supabase, Firebase, Vercel, Laravel, Django, Express, PHP/WordPress and mobile; 27 core controls each with a verification test.
- **Encryption & protection:** sensitive-data map encrypted by default; XChaCha20-Poly1305 or AES-256-GCM with per-field HKDF keys, record-bound AAD and blind indexes; peppered Argon2id; encrypted files and backups; key management and rotation; CDN/WAF, bot challenge, admin MFA, breached-password blocking, kill switch.
- **Monitoring & alerts:** blocks SQLi, XSS, traversal, command injection, SSRF, `.env`/`.git` probes, brute force and honeytoken use; alerts with type, IP, approximate location and path via email, webhook (Slack, Discord, Teams, n8n), Telegram and WhatsApp through n8n; Arabic/English dashboard, daily digest, monitor-only mode.
- **Reports & compliance:** branded client report (HTML + PDF, Arabic or English) with score and before/after; AI app security per OWASP GenAI LLM Top 10 2026; Saudi PDPL (K1–K12); NCA ECC-2:2024 and SAMA evidence mapping.
- **Quality:** 33 automated tests and a benchmark (40/40 detected, 0 false positives); works with Claude and any other LLM; single-file edition for pasting.

### What's new in v3

| Feature | What it does |
|---|---|
| 📄 Client report | `scripts/report.py`: branded HTML + PDF, Arabic RTL or English, 0–100 score and grade, before/after (resolved / new / still open), findings mapped to controls, next steps |
| 🔐 Authorization tests | `scripts/authz_test.py`: proves user A cannot read user B's data (IDOR), normal users cannot reach admin routes, protected routes reject anonymous users. Local-only by default; tokens from env |
| 🏗️ Infrastructure checks | Dockerfile, docker-compose, nginx/Apache, Kubernetes, Terraform, GitHub Actions |
| 🔧 Safe auto-fix | `--fix`: `.gitignore` entries, `.env.example`, review files (untrack script, RLS draft, security.txt, headers). Never edits code or deletes |
| 🔬 Deep mode | `--deep`: merges Semgrep, Gitleaks and Trivy results when installed |
| 📊 Alerts dashboard | `scripts/alerts_dashboard.py`: attack types, countries, top IPs, per-day chart, latest events; daily email digest |
| 📣 Alert channels | Email, webhook (Slack, Discord, Teams, n8n), Telegram, JSONL log |
| 🇸🇦 NCA ECC & SAMA | Maps skill evidence to the four NCA ECC-2:2024 domains and the SAMA Cyber Security Framework |
| ✅ Tests & benchmark | `tests/run_tests.py`: 33 tests, 40/40 planted issues detected, 0 false positives on a clean project; runs in GitHub Actions |

### Coverage

| Layer | Contents |
|---|---|
| Automated scanner | Secrets (files + git history), tracked sensitive files, public env misuse, dangerous code, missing RLS, vulnerable dependencies, infrastructure, live site (headers, cookies, CORS, HTTPS, exposed paths) |
| 27 core controls | Login, secrets, database, input, transport, headers, abuse, dependencies, review |
| Module E: Encryption (E1–E9) | Sensitive-data map encrypted by default, XChaCha20-Poly1305 / AES-256-GCM, HKDF per-field keys, blind index, peppered Argon2id, encrypted files and backups, key management and rotation |
| Module P: Protection (P1–P7) | CDN/WAF, bot challenge, admin MFA, breached-password blocking, tested backups, kill switch |
| Module D: Intrusion alerts (D1–D9) | Blocks attacks and alerts with type, IP, approximate location, path; dashboard and digest |
| Module I: Infrastructure (I1–I6) | Containers, compose, web server, Kubernetes, cloud/Terraform, CI/CD |
| Module Z: Authorization tests | IDOR, admin role checks, unauthenticated access |
| Module A: AI security (A1–A11) | OWASP GenAI LLM Top 10 2026 |
| Module S: Stack playbooks | Next.js, Supabase, Firebase, Vercel, Laravel, Django, Express, PHP/WordPress, mobile |
| Module K: Saudi PDPL (K1–K12) | Consent, Arabic privacy notice, data rights, 72-hour breach notification to SDAIA, cross-border transfers |
| Module N: NCA ECC / SAMA | Evidence mapping per domain; organizational controls flagged out of scope |

### Install

- **Claude (web / desktop / mobile):** download [`dist/vibe-security-hardening.zip`](dist/vibe-security-hardening.zip) → **Customize > Skills > + > Upload a skill** (existing skill: open it → **⋯ > Upload new version**).
- **Claude Code:** `git clone https://github.com/masari-aii/vibe-security-hardening ~/.claude/skills/vibe-security-hardening`
- **Any other model:** paste [`ALL-IN-ONE.md`](ALL-IN-ONE.md) as the system prompt or first message.
- **Coding agents (Cursor, Windsurf, ...):** copy the repo folder into the project and reference it in the project rules.

### Usage

Ask the model:
```text
Secure, encrypt and protect my project with the full skill, and give me the client report in English.
Stack: Next.js + Supabase + Vercel
```

Or run the tools yourself (Python 3.8+, no installs):
```bash
python3 scripts/scan.py ./my-app --url https://my-site.com --json before.json     # scan + baseline
python3 scripts/scan.py ./my-app --fix                                             # safe fixes
python3 scripts/authz_test.py authz.json --json authz-out.json                     # IDOR/admin tests (local)
python3 scripts/scan.py ./my-app --json after.json                                 # re-scan after fixes
python3 scripts/report.py after.json --baseline before.json --authz authz-out.json \
  --project "Client site" --brand "Masari AI" --lang en --pdf                     # client report
python3 scripts/alerts_dashboard.py alerts.jsonl --out dashboard.html --lang en    # attack dashboard
```

- **CI:** copy [`templates/security-scan.yml`](templates/security-scan.yml) to `.github/workflows/` and `scripts/scan.py` to `.security/scan.py`.
- **Intrusion alerts:** copy `scripts/guard.mjs` (Node.js) or `scripts/guard.py` (Python); configure `ALERT_TO`, `ALERT_WEBHOOK_URL`, `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID`, `ALERT_LOG_FILE`. See [`references/intrusion-alerts.md`](references/intrusion-alerts.md).
- **Full tool reference:** [`references/scanner.md`](references/scanner.md).

### Repository layout

```
SKILL.md                 core workflow + 27 controls + module index
ALL-IN-ONE.md            single-file edition for any LLM (generated)
references/              encryption, protection, intrusion-alerts, infrastructure, ai-security, stacks, pdpl, nca-ecc, scanner
docs/                    screenshots (docs/images) and sample PDF reports
scripts/                 scan.py, report.py, authz_test.py, guard.mjs, guard.py, alerts_dashboard.py
templates/               security-scan.yml (GitHub Actions for your project)
tests/                   run_tests.py (test suite + benchmark, runtime fixtures)
tools/build.py           builds ALL-IN-ONE.md and dist/ packages
dist/                    vibe-security-hardening.zip / .skill (Claude upload)
```

Run the tests: `python3 tests/run_tests.py` (optional extras: `pip install pynacl argon2-cffi cryptography` and `npm i express nodemailer` for the reference-code tests).

### Scope

Defensive use on systems you own or are authorized to test. A hardening pass, not a guarantee and not a substitute for a professional penetration test. IP locations are approximate. The PDPL and NCA modules are technical checklists, not legal advice.

---

<div align="center">

Built by **[Masari AI](https://github.com/masari-aii)** · [masari-ai.com](https://masari-ai.com) · MIT License

</div>
