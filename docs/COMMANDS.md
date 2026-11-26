<div dir="rtl">

# دليل الأوامر والاستخدام التفصيلي

[English version](COMMANDS.en.md) · [الصفحة الرئيسية](../README.md)

هذا الدليل يشرح كل أمر في المهارة: ماذا يفعل، وكل خياراته، وأمثلة جاهزة، وكيف تقرأ النتيجة. يمكنك استخدام المهارة بطريقتين: **تطلب من النموذج** (Claude أو غيره) وهو يشغّل الأدوات، أو **تشغّل الأدوات بنفسك** من الطرفية.

## المحتويات

1. [المتطلبات](#1-المتطلبات)
2. [فهرس سريع](#2-فهرس-سريع)
3. [أوامر للنموذج (اطلب بالكلام)](#3-أوامر-للنموذج-اطلب-بالكلام)
4. [الفاحص `scan.py`](#4-الفاحص-scanpy)
5. [اختبارات الصلاحيات `authz_test.py`](#5-اختبارات-الصلاحيات-authz_testpy)
6. [تقرير العميل `report.py`](#6-تقرير-العميل-reportpy)
7. [الحماية والتنبيهات `guard.mjs` / `guard.py`](#7-الحماية-والتنبيهات-guardmjs--guardpy)
8. [لوحة التنبيهات `alerts_dashboard.py`](#8-لوحة-التنبيهات-alerts_dashboardpy)
9. [الفحص التلقائي في GitHub Actions](#9-الفحص-التلقائي-في-github-actions)
10. [أوامر الصيانة: الاختبارات والبناء](#10-أوامر-الصيانة-الاختبارات-والبناء)
11. [سيناريوهات كاملة خطوة بخطوة](#11-سيناريوهات-كاملة-خطوة-بخطوة)
12. [حل المشاكل الشائعة](#12-حل-المشاكل-الشائعة)

---

## 1. المتطلبات

| المطلوب | لماذا | ملاحظات |
|---|---|---|
| Python 3.8 أو أحدث | لتشغيل كل الأدوات | بدون مكتبات إضافية. على Windows استخدم `python` بدل `python3` |
| Git | لفحص تاريخ Git | اختياري؛ بدونه يُتخطى فحص التاريخ |
| npm / pip-audit / composer | لفحص المكتبات المصابة | اختياري؛ يعمل الموجود منها فقط |
| Chrome أو Chromium أو Edge | لإخراج التقرير PDF | اختياري؛ بدونه افتح ملف HTML واطبعه PDF |
| Semgrep / Gitleaks / Trivy | للفحص العميق `--deep` | اختياري |
| Node.js + `express` + `nodemailer` | لحماية مواقع Node.js بـ `guard.mjs` | فقط إذا استخدمت الحماية في Node |

احصل على الأدوات:

```bash
git clone https://github.com/masari-aii/vibe-security-hardening
cd vibe-security-hardening
python3 scripts/scan.py --help
```

> كل أداة تعرض شرح خياراتها بالأمر `--help`.

---

## 2. فهرس سريع

| الأمر | ماذا يفعل | متى تستخدمه |
|---|---|---|
| `python3 scripts/scan.py ./مشروعي` | فحص كامل للكود وتاريخ Git والمكتبات والبنية التحتية | قبل الإطلاق وبعد كل ميزة كبيرة |
| `python3 scripts/scan.py ./مشروعي --url https://موقعي.com` | الفحص السابق + فحص الموقع المباشر | عندما يكون الموقع منشورًا |
| `python3 scripts/scan.py ./مشروعي --fix` | إصلاحات آمنة تلقائية | بعد أول فحص |
| `python3 scripts/scan.py ./مشروعي --json before.json` | حفظ النتائج لملف (للتقرير والمقارنة) | قبل الإصلاح وبعده |
| `python3 scripts/authz_test.py authz.json` | اختبار هل يرى مستخدم بيانات غيره | لأي موقع فيه تسجيل دخول |
| `python3 scripts/report.py after.json --baseline before.json --pdf` | تقرير احترافي للعميل | في نهاية الفحص |
| `python3 scripts/alerts_dashboard.py alerts.jsonl` | لوحة محاولات الاختراق | بعد تفعيل الحماية |
| `python3 scripts/alerts_dashboard.py alerts.jsonl --digest --send` | ملخص يومي بالإيميل | يوميًا بجدولة |
| `python3 tests/run_tests.py` | التأكد أن الأدوات تعمل | بعد أي تعديل على المهارة |

---

## 3. أوامر للنموذج (اطلب بالكلام)

بعد تركيب المهارة في Claude (أو لصق `ALL-IN-ONE.md` في أي نموذج)، اكتب طلبك بالعربي. أمثلة جاهزة:

| تريد | اكتب |
|---|---|
| فحص وإصلاح كامل | `أمّن وشفّر واحمِ مشروعي: طبّق المهارة كاملة. التقنيات: Next.js + Supabase + Vercel` |
| فحص فقط بدون تعديل | `افحص مشروعي فقط بدون تعديل أي ملف، وأعطني تقريرًا بالمشاكل مرتبة حسب الخطورة` |
| تقرير لعميل | `افحص المشروع وأعطني تقرير العميل بالعربي PDF باسم شركة Masari AI ومقارنة قبل وبعد` |
| المفاتيح المسرّبة فقط | `نفّذ البنود 2 و11 و24 و25 (المفاتيح والأسرار) على هذا المستودع` |
| الصلاحيات | `اختبر الصلاحيات: هل يستطيع مستخدم رؤية طلبات أو بيانات مستخدم آخر؟ وهل صفحات الأدمن محمية؟` |
| التشفير | `اعمل خريطة البيانات الحساسة في مشروعي وشفّر كل حقل حساس بأقوى إعدادات` |
| تنبيهات الاختراق | `فعّل كشف الاختراق في مشروعي وأرسل التنبيهات على إيميلي وتيليجرام` |
| البنية التحتية | `افحص Dockerfile و docker-compose و nginx وملفات Terraform في المشروع` |
| تطبيق ذكاء اصطناعي | `راجع أمان شات بوت الذكاء الاصطناعي في مشروعي حسب OWASP LLM Top 10` |
| نظام حماية البيانات | `هل مشروعي متوافق مع نظام حماية البيانات الشخصية السعودي؟ أعطني جدول K1 إلى K12` |
| ضوابط الهيئة الوطنية | `اربط نتائج الفحص بضوابط NCA ECC للعميل الحكومي` |
| فحص تلقائي مستمر | `أضف الفحص الأمني التلقائي إلى GitHub Actions في مشروعي` |

**نصائح:**
- اذكر التقنيات المستخدمة (الإطار، قاعدة البيانات، الاستضافة) ليختار النموذج دليل الإصلاح المناسب.
- في محادثة بدون وصول للملفات: الصق الملفات المهمة (المصادقة، مسارات API، قواعد قاعدة البيانات، الإعدادات)، أو شغّل `scan.py` بنفسك والصق النتيجة.
- النموذج يطلب موافقتك قبل أي خطوة لا يمكن التراجع عنها (تبديل المفاتيح، حذف تاريخ Git، تعديل قاعدة بيانات حية).

---

## 4. الفاحص `scan.py`

### ماذا يفعل
يفحص مشروعك ويطبع كل مشكلة مع خطورتها وموقعها والإجراء المطلوب. لا يعدّل أي ملف إلا مع `--fix` (وحتى عندها لا يلمس الكود).

### الصيغة
```bash
python3 scripts/scan.py [مسار_المشروع] [الخيارات]
```

### الخيارات

| الخيار | ماذا يفعل | مثال |
|---|---|---|
| `path` | مجلد المشروع. الافتراضي المجلد الحالي | `./my-app` |
| `--url URL` | يضيف فحص الموقع المباشر: HTTPS، الهيدرز، الكوكيز، CORS، الملفات المكشوفة. **موقعك فقط** | `--url https://shop.com` |
| `--json FILE` | يحفظ النتائج في ملف JSON (للتقرير والمقارنة و CI) | `--json before.json` |
| `--fail-on LEVEL` | يجعل الأمر ينتهي برمز 1 إذا وُجدت مشكلة بهذه الخطورة أو أعلى. القيم: `critical` (الافتراضي)، `high`، `medium`، `low`، `info` | `--fail-on high` |
| `--no-history` | يتخطى فحص تاريخ Git (أسرع) | |
| `--no-deps` | يتخطى فحص المكتبات (npm/pip/composer) | |
| `--no-infra` | يتخطى فحص Docker و nginx و Kubernetes و Terraform و CI | |
| `--deep` | يدمج نتائج Semgrep و Gitleaks و Trivy إن كانت مثبتة | |
| `--fix` | إصلاحات آمنة تلقائية (التفاصيل أدناه) | |
| `-h`, `--help` | يعرض الشرح | |

### أمثلة حسب الحالة

```bash
# فحص كامل
python3 scripts/scan.py ./my-app

# فحص سريع أثناء التطوير
python3 scripts/scan.py ./my-app --no-history --no-deps

# فحص المشروع والموقع المنشور وحفظ النتائج
python3 scripts/scan.py ./my-app --url https://my-site.com --json scan.json

# فحص الموقع فقط (بدون كود)
python3 scripts/scan.py . --no-history --no-deps --no-infra --url https://my-site.com

# فحص صارم: يفشل عند أي مشكلة عالية أو حرجة (مناسب لـ CI)
python3 scripts/scan.py . --fail-on high

# فحص عميق بأدوات إضافية
python3 scripts/scan.py ./my-app --deep
```

### كيف تقرأ النتيجة

```
summary: critical=2  high=3  medium=1  low=0  info=0
[CRITICAL] C24  Secret in git history: Stripe live secret key  @ commit b4aac5aa34  — value …K6J0 — revoke and rotate it (C25)
[HIGH    ] C10  SQL built by string concatenation/interpolation  @ src/api.js:2  — query(`SELECT * FROM users WHERE id = ${
```

| الجزء | المعنى |
|---|---|
| `summary` | عدد المشاكل حسب الخطورة |
| `[CRITICAL]` | الخطورة: حرج ← عالٍ ← متوسط ← منخفض ← معلومة |
| `C24` | رمز البند (الجدول التالي) |
| النص بعده | وصف المشكلة |
| `@ ...` | الموقع: `ملف:سطر`، أو رقم الـ commit، أو رابط الصفحة |
| `— ...` | الإجراء المطلوب أو جزء من الكود |
| `…K6J0` | المفاتيح تظهر بآخر 4 أحرف فقط حتى لا تتسرب |

**رموز البنود:**

| الرمز يبدأ بـ | المجال | أمثلة |
|---|---|---|
| `C` | البنود الأساسية الـ27 | `C2` مفتاح في ملف، `C3` قاعدة بيانات، `C10` حقن SQL، `C11` متغيرات البيئة، `C24` تاريخ Git |
| `E` | التشفير | `E2` تعطيل التحقق من TLS، `E6` توكنات وعشوائية ضعيفة |
| `I` | البنية التحتية | `I1` Docker، `I2` compose، `I3` nginx، `I4` Kubernetes، `I5` السحابة، `I6` GitHub Actions |
| `A` | الذكاء الاصطناعي | `A1` إدخال المستخدم داخل تعليمات النظام |
| `P` | الحماية | `P6` ملف security.txt |
| `Z` | الصلاحيات (من `authz_test.py`) | `Z1` بدون تسجيل دخول، `Z2` أدمن، `Z3` IDOR |
| `SEM` | Semgrep (الفحص العميق) | |

**رمز الخروج:** `0` لا توجد مشكلة بمستوى `--fail-on`، و `1` توجد. مفيد في السكربتات و CI.

### ماذا يفعل `--fix` بالضبط
لا يعدّل الكود، لا يحذف، ولا يغيّر تاريخ Git. فقط:

| الإجراء | الملف |
|---|---|
| يضيف `.env` والمفاتيح والنسخ الاحتياطية إلى `.gitignore` | `.gitignore` |
| ينشئ ملف المتغيرات بالأسماء فقط بدون قيم | `.env.example` |
| سكربت لإزالة الملفات الحساسة من Git (للمراجعة ثم التشغيل) | `.security/untrack-sensitive-files.sh` |
| مسودة تفعيل RLS مع قوالب السياسات | `.security/draft-enable-rls.sql` |
| قالب ملف التواصل الأمني | `.security/security.txt` |
| هيدرز الأمان المقترحة | `.security/security-headers.txt` |

تكراره آمن. **مهم:** تفعيل RLS بدون سياسات يمنع كل الوصول للجدول، لذلك الملف مسودة تراجعها أولًا. وأي مفتاح ظهر في تاريخ Git يجب إلغاؤه وتبديله من لوحة المزوّد حتى بعد إزالته.

### كتم إنذار خاطئ
بعد مراجعة المشكلة والتأكد أنها ليست ثغرة:
```js
el.innerHTML = trustedStaticHtml; // vibe-scan: ignore
```
أو ضع `vibe-scan: ignore-file` في أول الملف لتجاهله كله. اذكر السبب في التقرير.

### الفحص العميق `--deep`
- يعمل فقط بالأدوات المثبتة، ويخبرك بالناقص.
- Semgrep يستخدم قواعد `p/default` من الإنترنت. إذا كانت الشبكة مقيدة، حدد مجلد قواعد محلي:
```bash
SEMGREP_CONFIG=./my-semgrep-rules python3 scripts/scan.py . --deep
```

---

## 5. اختبارات الصلاحيات `authz_test.py`

### ماذا يفعل
يثبت أن كل مستخدم يصل لبياناته فقط، وأن المستخدم العادي لا يدخل صفحات الأدمن، وأن الصفحات المحمية لا تُفتح بدون تسجيل دخول. هذا النوع من الثغرات (IDOR) لا يكتشفه الفحص العادي.

### الأمان أولًا
- يعمل افتراضيًا على `localhost` و `127.0.0.1` ونطاقات `.test` و `.local` فقط. لموقع تملكه أو مصرّح لك باختباره أضف `--allow-remote`.
- طلبات `DELETE` لا تُنفذ إلا مع `--allow-destructive`.
- التوكنات تؤخذ من متغيرات البيئة، لا تُكتب في الملف.

### الصيغة
```bash
python3 scripts/authz_test.py authz.json [--json results.json] [--allow-remote] [--allow-destructive]
```

| الخيار | ماذا يفعل |
|---|---|
| `config` | ملف الإعداد (الشكل أدناه) |
| `--json FILE` | يحفظ النتائج لدمجها في التقرير (`report.py --authz`) |
| `--allow-remote` | يسمح بهدف غير محلي (موقعك أو المصرّح لك به فقط) |
| `--allow-destructive` | يسمح باختبارات `DELETE` |

### ملف الإعداد `authz.json`

```json
{
  "base_url": "http://localhost:3000",
  "users": {
    "alice": {"headers": {"Authorization": "Bearer ${ALICE_TOKEN}"}},
    "bob":   {"headers": {"Authorization": "Bearer ${BOB_TOKEN}"}},
    "admin": {"headers": {"Cookie": "session=${ADMIN_SESSION}"}}
  },
  "checks": [
    {"name": "طلب Alice رقم 101", "method": "GET", "path": "/api/orders/101", "owner": "alice", "deny": ["anonymous", "bob"]},
    {"name": "قائمة المستخدمين", "method": "GET", "path": "/api/admin/users", "owner": "admin", "deny": ["anonymous", "alice", "bob"]},
    {"name": "Bob يعدّل حساب Alice", "method": "PATCH", "path": "/api/users/1", "body": {"name": "x"}, "owner": "alice", "deny": ["bob"]}
  ]
}
```

| الحقل | المعنى |
|---|---|
| `base_url` | عنوان التطبيق (نسخة محلية أو تجريبية) |
| `users` | المستخدمون وطريقة دخولهم (هيدر Authorization أو Cookie). `${اسم}` تُستبدل بقيمة متغير البيئة |
| `anonymous` | مستخدم مدمج بدون تسجيل دخول، لا تحتاج تعريفه |
| `checks[].name` | اسم وصفي للاختبار |
| `checks[].method` | `GET` (الافتراضي) أو `POST` أو `PATCH` أو `PUT` أو `DELETE` |
| `checks[].path` | المسار المطلوب اختباره |
| `checks[].body` | محتوى الطلب (اختياري، JSON) |
| `checks[].owner` | صاحب البيانات: يجب أن يصل (تأكيد أن الإعداد صحيح) |
| `checks[].deny` | من يجب أن يُمنع |
| `deny_status` | (اختياري) رموز المنع المقبولة. الافتراضي `[401, 403, 404]` |

**كيف تبني القائمة:** خذ كل مسار فيه رقم أو معرّف (`/orders/:id` و `/users/:id` و `/invoices/:id`) وكل مسار يبدأ بـ `admin`، واختبره بصاحب البيانات ومستخدم آخر وبدون تسجيل دخول.

### التشغيل

```bash
# Linux / macOS
ALICE_TOKEN=xxx BOB_TOKEN=yyy ADMIN_SESSION=zzz python3 scripts/authz_test.py authz.json --json authz.out.json
```
```powershell
# Windows PowerShell
$env:ALICE_TOKEN="xxx"; $env:BOB_TOKEN="yyy"; $env:ADMIN_SESSION="zzz"
python scripts/authz_test.py authz.json --json authz.out.json
```

### كيف تقرأ النتيجة

```
[PASS  ] طلب Alice رقم 101   anonymous -> 401
[FAIL  ] طلب Alice رقم 101   bob -> 200
[CONFIG] قائمة المستخدمين     owner 'admin' got 401: fix the config/credentials first
```

| الحالة | المعنى | ماذا تفعل |
|---|---|---|
| `PASS` | المستخدم مُنع كما يجب | لا شيء |
| `FAIL` + `anonymous -> 200` | صفحة محمية تُفتح بدون تسجيل دخول (Z1، حرج) | أضف التحقق من الجلسة في الخادم |
| `FAIL` + مستخدم عادي على مسار أدمن | خلل في صلاحيات الأدمن (Z2، حرج) | تحقق من الدور في الخادم لكل مسار أدمن |
| `FAIL` + مستخدم آخر على بيانات غيره | ثغرة IDOR (Z3، عالٍ) | تحقق أن السجل يخص المستخدم الحالي |
| `CONFIG` | صاحب البيانات نفسه لم يصل | التوكن منتهي أو المسار خطأ؛ صحّح الإعداد |
| `SKIP` | اختبار `DELETE` بدون `--allow-destructive` | أضف الخيار إن أردت (على نسخة تجريبية) |

**رمز الخروج:** `1` إذا فشل أي اختبار، و `0` إذا نجحت كلها.

---

## 6. تقرير العميل `report.py`

### ماذا يفعل
يحوّل نتائج الفحص إلى تقرير احترافي بشعارك: درجة أمان من 100، تقدير، مقارنة قبل وبعد، جدول النتائج، والخطوات الموصى بها. HTML دائمًا، و PDF اختياريًا.

### الصيغة
```bash
python3 scripts/report.py scan.json [الخيارات]
```

| الخيار | ماذا يفعل | الافتراضي |
|---|---|---|
| `scan` | ملف JSON من `scan.py --json` (الوضع الحالي) | مطلوب |
| `--baseline FILE` | ملف فحص سابق لعرض المقارنة قبل وبعد | بدون |
| `--authz FILE` | نتائج `authz_test.py --json` لإضافتها | بدون |
| `--manual FILE` | نتائج المراجعة اليدوية (الشكل أدناه) | بدون |
| `--project NAME` | اسم المشروع أو العميل | `Web application` |
| `--brand NAME` | اسم شركتك أعلى التقرير | `Security report` |
| `--logo FILE/URL` | شعارك (ملف صورة أو رابط) | بدون |
| `--color HEX` | لون العلامة | `#2563eb` |
| `--lang ar\|en` | لغة التقرير | `ar` |
| `--out FILE` | اسم ملف HTML | `security-report.html` |
| `--pdf` | ينشئ PDF بجانبه (يحتاج Chrome أو Chromium أو Edge) | بدون |

### أمثلة

```bash
# تقرير بسيط
python3 scripts/report.py scan.json --project "موقع العميل"

# تقرير كامل بشعارك ومقارنة واختبارات الصلاحيات و PDF
python3 scripts/report.py after.json --baseline before.json --authz authz.out.json \
  --project "متجر العميل" --brand "Masari AI" --logo logo.png --color "#1d4ed8" --lang ar --pdf

# نسخة إنجليزية من نفس التقرير
python3 scripts/report.py after.json --baseline before.json --lang en --out report-en.html --pdf
```

### كيف تُحسب الدرجة
- تبدأ من 100 وتنقص حسب الخطورة: حرج 15 نقطة، عالٍ 7، متوسط 3، منخفض 1، بانحدار تدريجي حتى يبقى التحسن ظاهرًا.
- **وجود أي مشكلة حرجة يحدّ الدرجة عند 59** مهما كانت بقية النتائج.
- التقدير: A من 90، B من 75، C من 60، D من 40، وأقل F.
- مثال: مشكلة عالية واحدة = 92، مشكلة حرجة واحدة = 59، لا مشاكل = 100.

### ملف المراجعة اليدوية `manual.json`
للمشاكل التي وجدتها بنفسك (منطق العمل، الدفع...):
```json
[
  {"control": "C19", "severity": "critical", "title": "السعر يُرسل من المتصفح ويُقبل كما هو", "where": "api/checkout.ts:42", "detail": "احسب السعر في الخادم من قاعدة البيانات"}
]
```

### قراءة التقرير
- **الدائرة:** الدرجة (أخضر 75 فأكثر، أصفر 50 إلى 74، أحمر أقل من 50).
- **البطاقات:** عدد المشاكل لكل خطورة.
- **قبل وبعد:** الدرجة السابقة ← الحالية، وما **تم حله** (أخضر)، وما **استجد** (أحمر)، وما **بقي مفتوحًا**.
- **الجدول:** الخطورة، البند، المجال، المشكلة، الموقع، الإجراء.

---

## 7. الحماية والتنبيهات `guard.mjs` / `guard.py`

### ماذا تفعل
تفحص كل طلب يصل لموقعك. عند اكتشاف هجوم (حقن SQL، XSS، تجاوز المسارات، حقن أوامر، SSRF، محاولة الوصول لـ `.env` أو `.git`، تخمين كلمات المرور) تحجبه وترسل تنبيهًا فيه: نوع الهجوم، الوقت، عنوان IP، الموقع التقريبي، الصفحة المستهدفة، والإجراء المقترح.

### التركيب في Node.js (Express)

```bash
npm i nodemailer
cp vibe-security-hardening/scripts/guard.mjs ./security/guard.mjs
```
```js
import express from 'express';
import { guard, onLoginFailure, onAccessDenied, onHoneytoken } from './security/guard.mjs';

const app = express();
app.set('trust proxy', 1);        // عدد طبقات البروكسي الفعلية (Cloudflare = 1)
app.use(express.json());
app.use(guard());                 // قبل كل المسارات

app.post('/login', async (req, res) => {
  const ok = await checkPassword(req.body.email, req.body.password);
  if (!ok) { await onLoginFailure(req, req.body.email); return res.status(401).end(); }
  // ...
});
// عند رفض صلاحية:   await onAccessDenied(req, `${req.method} ${req.path}`);
// عند استخدام حساب فخ: await onHoneytoken(req, 'decoy admin');
```

### التركيب في Python (Flask)

```bash
cp vibe-security-hardening/scripts/guard.py ./security/guard.py
```
```python
import os
from flask import Flask, request, abort
from security.guard import inspect

app = Flask(__name__)

@app.before_request
def _guard():
    ip = request.headers.get("CF-Connecting-IP", request.remote_addr)
    attack, _ = inspect(ip, dict(request.headers), request.method, request.path,
                        request.query_string.decode(), request.get_data(as_text=True)[:5000])
    if attack and os.environ.get("GUARD_MODE", "block") != "monitor":
        abort(404 if attack.startswith("Probe") else 400)
```

### متغيرات البيئة (قنوات التنبيه والإعدادات)

| المتغير | القناة / الوظيفة | مثال |
|---|---|---|
| `ALERT_TO` | إيميل الاستقبال | `security@masari-ai.com` |
| `ALERT_FROM` | إيميل الإرسال | `alerts@masari-ai.com` |
| `ALERT_SMTP_URL` | خادم البريد (Node) | `smtps://user:pass@smtp.hostinger.com:465` |
| `ALERT_SMTP_HOST` / `PORT` / `USER` / `PASS` | خادم البريد (Python) | `smtp.hostinger.com` / `587` / ... |
| `ALERT_WEBHOOK_URL` | Slack أو Discord أو Teams أو n8n أو أي Webhook | `https://hooks.slack.com/services/...` |
| `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | تيليجرام | من BotFather + رقم المحادثة |
| `ALERT_LOG_FILE` | ملف السجل للوحة | `/var/log/myapp/alerts.jsonl` |
| `GUARD_MODE` | `block` يحجب ويرسل (الافتراضي)، `monitor` يرسل فقط بدون حجب | `monitor` |

**واتساب:** وجّه `ALERT_WEBHOOK_URL` إلى سير عمل في n8n أو Zapier يرسل لرقمك عبر WhatsApp Business.

**نصائح:**
- ابدأ بـ `GUARD_MODE=monitor` لأيام قليلة لتتأكد أنه لا يحجب زوارًا حقيقيين، ثم غيّره إلى `block`.
- إيميل واحد لكل IP ولكل نوع هجوم كل 10 دقائق، وكل محاولة تُسجّل في `ALERT_LOG_FILE`.
- لإظهار المدينة والدولة: فعّل في Cloudflare خيار "Add visitor location headers".

### اختبار أن التنبيه يعمل

```bash
curl "http://localhost:3000/search?q=%27%20OR%201=1%20--"   # حقن SQL: يجب أن يُحجب برمز 400 ويصلك تنبيه
curl "http://localhost:3000/.env"                          # محاولة ملف حساس: 404 + تنبيه
curl "http://localhost:3000/search?q=shoes"                # طلب عادي: يمر
```

---

## 8. لوحة التنبيهات `alerts_dashboard.py`

### ماذا تفعل
تقرأ سجل التنبيهات (`ALERT_LOG_FILE`) وتنشئ لوحة HTML: إجمالي المحاولات، الأنواع، الدول، أكثر العناوين هجومًا، أكثر الصفحات استهدافًا، المحاولات يوميًا، وآخر 50 حدثًا. أو تطبع ملخصًا يوميًا وترسله بالإيميل.

### الصيغة والخيارات

```bash
python3 scripts/alerts_dashboard.py ملف_السجل [ملفات أخرى] [الخيارات]
```

| الخيار | ماذا يفعل | الافتراضي |
|---|---|---|
| `logs` | ملف سجل أو أكثر (JSONL، أو سجلات فيها أسطر `[SECURITY]`) | مطلوب |
| `--out FILE` | ملف اللوحة | `security-dashboard.html` |
| `--days N` | عدد الأيام المعروضة | `30` |
| `--brand NAME` | اسم شركتك | `Security` |
| `--lang ar\|en` | اللغة | `ar` |
| `--digest` | يطبع ملخص آخر 24 ساعة بدل اللوحة | |
| `--send` | مع `--digest`: يرسله بالإيميل (متغيرات `ALERT_SMTP_*` و `ALERT_TO`) | |

### أمثلة

```bash
python3 scripts/alerts_dashboard.py alerts.jsonl --out dashboard.html --brand "Masari AI"
python3 scripts/alerts_dashboard.py alerts.jsonl --lang en --days 7 --out week.html
python3 scripts/alerts_dashboard.py alerts.jsonl --digest
python3 scripts/alerts_dashboard.py alerts.jsonl --digest --send
```

### الملخص اليومي التلقائي

```bash
# Linux (crontab -e): كل يوم الساعة 8 صباحًا
0 8 * * * cd /srv/app && python3 security/alerts_dashboard.py /var/log/myapp/alerts.jsonl --digest --send
```
على Windows: استخدم Task Scheduler لتشغيل نفس الأمر يوميًا.

---

## 9. الفحص التلقائي في GitHub Actions

### الإعداد (مرة واحدة)

```bash
mkdir -p .github/workflows .security
cp vibe-security-hardening/templates/security-scan.yml .github/workflows/security-scan.yml
cp vibe-security-hardening/scripts/scan.py .security/scan.py
git add .github .security && git commit -m "Add security scan" && git push
```

اختياري: لفحص موقعك المنشور أيضًا، في GitHub: **Settings > Secrets and variables > Actions > Variables** أضف `SITE_URL` بقيمة `https://موقعك.com`.

### ماذا يحدث بعدها
- يعمل الفحص عند كل رفع وكل Pull Request وكل يوم اثنين.
- يفشل البناء (علامة حمراء) إذا وُجدت مشكلة عالية أو حرجة، فلا تُدمج ثغرة بالخطأ.
- تقرير JSON يُحفظ في صفحة التشغيل (Artifacts) لمدة 30 يومًا.

لتغيير الصرامة عدّل `--fail-on high` في الملف إلى `critical` أو `medium`.

---

## 10. أوامر الصيانة: الاختبارات والبناء

```bash
# تشغيل الاختبارات ومقياس الدقة (33 اختبارًا)
python3 tests/run_tests.py
python3 tests/run_tests.py --json benchmark.json

# لاختبار أكواد التشفير وحماية Node أيضًا
pip install pynacl argon2-cffi cryptography
npm i --no-save express nodemailer

# بناء ملف ALL-IN-ONE.md وحزمة المهارة dist/vibe-security-hardening.zip
python3 tools/build.py
```

---

## 11. سيناريوهات كاملة خطوة بخطوة

### أ) فحص مشروعي قبل الإطلاق

```bash
python3 scripts/scan.py ./my-app --json before.json        # 1. الفحص الأول
python3 scripts/scan.py ./my-app --fix                     # 2. الإصلاحات الآمنة
#                                                            3. أصلح الباقي (أو اطلب من النموذج)
python3 scripts/scan.py ./my-app --json after.json         # 4. أعد الفحص حتى لا يبقى حرج أو عالٍ
```
وأي مفتاح ظهر في النتائج: ألغه وبدّله من لوحة المزوّد فورًا.

### ب) خدمة فحص أمني لعميل مع تقرير

```bash
python3 scripts/scan.py ./client-app --url https://client.com --json before.json
ALICE_TOKEN=... BOB_TOKEN=... ADMIN_TOKEN=... python3 scripts/authz_test.py authz.json --json authz-before.json
#   ... الإصلاحات ...
python3 scripts/scan.py ./client-app --url https://client.com --json after.json
ALICE_TOKEN=... BOB_TOKEN=... ADMIN_TOKEN=... python3 scripts/authz_test.py authz.json --json authz-after.json
python3 scripts/report.py after.json --baseline before.json --authz authz-after.json \
  --project "العميل" --brand "Masari AI" --logo logo.png --lang ar --pdf
```
سلّم العميل ملف PDF، ومعه نسخة إنجليزية إن احتاج (`--lang en`).

### ج) تفعيل المراقبة بعد الإطلاق
1. انسخ `guard.mjs` أو `guard.py` واربطه (القسم 7).
2. اضبط `ALERT_TO` وقناة إضافية (`ALERT_WEBHOOK_URL` أو تيليجرام) و `ALERT_LOG_FILE`.
3. ابدأ بـ `GUARD_MODE=monitor`، جرّب أوامر `curl` في القسم 7، ثم بعد أيام غيّره إلى `block`.
4. جدول الملخص اليومي (القسم 8)، وافتح اللوحة أسبوعيًا.

### د) فحص مستمر لكل تعديل
اتبع القسم 9. بعدها أي Pull Request يدخل ثغرة عالية أو حرجة سيظهر بعلامة حمراء قبل الدمج.

---

## 12. حل المشاكل الشائعة

| المشكلة | السبب والحل |
|---|---|
| `python3: command not found` | على Windows استخدم `python`. تأكد أن Python 3.8+ مثبت |
| فحص تاريخ Git تخطّى | المجلد ليس مستودع Git أو Git غير مثبت |
| `npm audit failed` | لا يوجد `package-lock.json` أو لا يوجد اتصال بالإنترنت؛ أو استخدم `--no-deps` |
| `pip-audit not installed` | `pip install pip-audit` (اختياري) |
| `semgrep returned no results for config 'p/default'` | الشبكة تمنع تحميل القواعد؛ استخدم `SEMGREP_CONFIG=مجلد_قواعد_محلي` |
| إنذار خاطئ | راجعه، ثم أضف `// vibe-scan: ignore` على السطر واذكر السبب في التقرير |
| `refusing non-local target` في اختبار الصلاحيات | الحماية تعمل؛ اختبر نسخة محلية، أو أضف `--allow-remote` لموقع تملكه |
| `CONFIG` في اختبار الصلاحيات | توكن صاحب البيانات منتهي أو المسار خطأ |
| لم يُنشأ PDF | لا يوجد Chrome أو Chromium أو Edge؛ افتح HTML واطبعه PDF |
| الموقع في التنبيه `unknown` | فعّل ترويسات الموقع في Cloudflare، أو استخدم قاعدة GeoIP |
| التنبيهات كثيرة | التنبيهات مقيدة بإيميل لكل IP ونوع كل 10 دقائق؛ احجب العناوين المتكررة في جدار الحماية |
| حماية Node تحجب طلبًا عاديًا | شغّل `GUARD_MODE=monitor` وراجع السجل، وأبلغنا بالمثال |

> للأنظمة التي تملكها أو المصرّح لك باختبارها فقط. هذه أدوات تقوية وليست ضمانًا أو بديلًا عن اختبار اختراق احترافي.

</div>
