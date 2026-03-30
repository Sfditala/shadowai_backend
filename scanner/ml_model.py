# ================================================================
# ShadowAI Detector — النموذج الذكي لكشف تسريب البيانات
# ================================================================
# الهدف: يأخذ نص → يحلله → يرجع تصنيف (critical / high / medium / safe)
# ⚠️ شغل هاد الملف مرة وحدة عشان يدرب ويحفظ النموذج
#
# ══════════════════════════════════════════════════════════
# منهجية التصنيف (كمهندس AI محترف):
# ══════════════════════════════════════════════════════════
#
# 🔴 CRITICAL: بيانات تسبب ضرراً فورياً لو تسربت
#   - كلمات مرور حقيقية (مش بالكود!)
#   - مفاتيح API وتوكنات سرية
#   - أرقام بطاقات ائتمان
#   - مفاتيح تشفير خاصة
#
# 🔴 HIGH: بيانات شخصية تنتهك الخصوصية
#   - إيميل + معلومات تعريفية أخرى
#   - هاتف + معلومات تعريفية أخرى
#   - أرقام هوية / جوازات
#   - عناوين سكن تفصيلية
#   - معلومات طبية شخصية
#   - أسماء مرفقة بمعلومات حساسة
#
# 🟠 MEDIUM: معلومات حساسة لكن وحدها لا تكفي للاحتيال
#   - إيميل مجرد (بدون معلومات إضافية)
#   - هاتف مجرد
#   - راتب / دخل مالي
#   - روابط قواعد بيانات
#   - بورتات وإعدادات سيرفر
#
# 🟢 SAFE: كل شيء آمن
#   - كود برمجي (حتى لو فيه كلمة password!)
#   - أسئلة تعليمية
#   - محادثات عامة
#   - أسماء مجردة بدون معلومات حساسة
#   - وصف جسدي عام (وزن / طول)
#
# ══════════════════════════════════════════════════════════
# القاعدة الذهبية: السياق يحدد التصنيف
# "password" بالكود = safe
# "password=Admin123" = critical
# ══════════════════════════════════════════════════════════
# ================================================================

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

data = [
    # ================================================================
    # 🔴 CRITICAL — تسريبها يسبب ضرراً فورياً
    # ================================================================
    # ── أرقام بطاقات ائتمان ──
    ("رقم بطاقتي 4532015112830366", "critical"),
    ("card number 4532015112830366 expiry 12/26", "critical"),
    ("my credit card is 5500005555555559", "critical"),
    ("بطاقتي الائتمانية 4111111111111111", "critical"),
    ("credit card: 4916338506082832 cvv 123", "critical"),
    ("visa card 4539578763621486", "critical"),
    ("mastercard 5425233430109903 exp 09/27", "critical"),
    ("رقم الكارت 4716184360702308", "critical"),
    ("my card number is 4929420209979305", "critical"),
    ("بطاقة الدفع 5105105105105100", "critical"),
    ("card: 4532015112830366, expiry: 12/26, cvv: 123", "critical"),
    ("pay with 4916338506082832", "critical"),
    ("رقم فيزا كارد 4485275742308327", "critical"),
    ("my mastercard number 5105105105105100 cvv 456", "critical"),
    ("بطاقتي الائتمانية رقم 4539578763621486", "critical"),
    ("كارت الدفع: 4111 1111 1111 1111", "critical"),
    ("card no: 5500-0055-5555-5559", "critical"),
    ("رقم بطاقة الصراف: 4532 0151 1283 0366", "critical"),
    ("credit: 4916-3385-0608-2832 exp: 12/26", "critical"),
    ("cvv البطاقة: 392 رقم البطاقة 4532015112830366", "critical"),
    ("card cvv is 847 for card 4929420209979305", "critical"),
    # ── كلمات مرور حقيقية (مش بالكود!) ──
    # القاعدة: لو في = أو : بعدها قيمة فعلية = critical
    ("password=MySecret123 للدخول", "critical"),
    ("passwd: Admin@2024", "critical"),
    ("كلمة المرور=Pass@word1", "critical"),
    ("كلمة السر: Admin123!", "critical"),
    ("my password is P@ssw0rd123", "critical"),
    ("login password: SuperSecret99", "critical"),
    ("pwd=qwerty123456", "critical"),
    ("كلمة السر للنظام Admin@2024", "critical"),
    ("password for server: MyP@ss123", "critical"),
    ("user password = Secure#Pass1", "critical"),
    ("الباسورد: Test123!", "critical"),
    ("new password: Ch@ngeMe123", "critical"),
    ("temp password is Hello@World1", "critical"),
    ("password : Admin2024!", "critical"),
    ("كلمة مرور الشبكة: Network@123", "critical"),
    ("my wifi password is Home@2024", "critical"),
    ("database password = Db#Secret99", "critical"),
    ("الرمز السري: 1234@Abcd", "critical"),
    ("server password: Linux@Root1", "critical"),
    ("كلمة المرور الجديدة: NewPass@2024", "critical"),
    ("ftp password=FtpUser@123", "critical"),
    ("email password: Mail@Secret1", "critical"),
    ("vpn password = VPN#Access2024", "critical"),
    ("كلمة سر الراوتر: Router@Admin1", "critical"),
    ("system password is Sys@Pass123", "critical"),
    ("ssh password: SSH@Secure99", "critical"),
    ("بكلمة المرور: Admin@2024 تقدر تدخل", "critical"),
    ("استخدم الباسورد هاد: Welcome@123", "critical"),
    ("كلمة المرور المؤقتة: Temp@Pass1", "critical"),
    ("رمز الدخول: Access@Code2024", "critical"),
    ("بعتلك كلمة المرور: Pass@word123", "critical"),
    ("هاد الباسورد للنظام: System@Pass1", "critical"),
    ("اكيد هذا باسورد السيرفر: Server@2024", "critical"),
    ("DATABASE_PASSWORD=MyDbPass@2024", "critical"),
    ("REDIS_PASSWORD=Redis@Secret123", "critical"),
    ("MONGO_PASSWORD=MongoPass@2024", "critical"),
    ("MYSQL_ROOT_PASSWORD=Root@MySQL2024", "critical"),
    ("POSTGRES_PASSWORD=Postgres@Pass1", "critical"),
    ("p12 password: CertPass@2024", "critical"),
    ("keystore password: KeyStore@123", "critical"),
    ("wallet password: Wallet@Crypto1", "critical"),
    ("login: admin pass: Admin123", "critical"),
    # ── مفاتيح API وتوكنات ──
    ("api_key=sk-abc123def456ghi789jkl", "critical"),
    ("secret_key=ghp_xxxxxxxxxxxxxxxxxxxx", "critical"),
    ("access_token=ya29.xxxxxxxxxxxxxxxx", "critical"),
    ("api key: sk-proj-abcdefghijklmnop", "critical"),
    ("github token: ghp_1234567890abcdef", "critical"),
    ("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG", "critical"),
    ("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "critical"),
    ("stripe_secret_key=sk_live_abcdefghijk", "critical"),
    ("STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc", "critical"),
    ("bearer token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "critical"),
    ("JWT_SECRET=mysupersecretjwtkey123", "critical"),
    ("encryption_key=aes256keyabcdefghij", "critical"),
    ("oauth_token=gho_16C7e42F292c6912E7710c838347Ae178B4a", "critical"),
    ("مفتاح API: sk-abc123def456", "critical"),
    ("التوكن السري: Bearer abc123xyz", "critical"),
    ("OPENAI_API_KEY=sk-proj-abc123def456ghi789", "critical"),
    ("firebase_api_key=AIzaSyAbCdEfGhIjKlMnOp", "critical"),
    ("twilio_auth_token=abcdef1234567890abcdef", "critical"),
    ("sendgrid_api_key=SG.abc123def456ghi789jkl", "critical"),
    ("paypal_client_secret=AbCdEfGhIjKlMnOpQrSt", "critical"),
    ("GOOGLE_CLIENT_SECRET=GOCSPX-abcdefghijklmno", "critical"),
    ("facebook_app_secret=abcdef1234567890", "critical"),
    ("discord_bot_token=MTA0abc.def.ghijklmnop", "critical"),
    ("telegram_bot_token=1234567890:ABCdefGHI", "critical"),
    ("heroku_api_key=abcdef12-3456-789a-bcde-f0123456789a", "critical"),
    ("cloudflare_api_token=abcdefghijklmnopqrstu", "critical"),
    ("SECRET=super_secret_key_123456789", "critical"),
    ("APP_SECRET=myappsecret123456", "critical"),
    ("ENCRYPTION_KEY=32charslongsecretkey123456", "critical"),
    ("signing_secret=abcdefghijklmnop123456", "critical"),
    ("webhook_secret=whsec_abcdefghijklmnop", "critical"),
    ("client_secret=AbCdEfGhIjKlMnOpQrStUvWx", "critical"),
    ("refresh_token=1//abcdefghijklmnopqrstuvwxyz", "critical"),
    ("session_secret=mysessionsecret123", "critical"),
    ("HASH_KEY=myhashkey123456789abcdef", "critical"),
    ("NEXTAUTH_SECRET=nextauthsecret123456789", "critical"),
    ("COOKIE_SECRET=cookiesecret123456789", "critical"),
    ("اعطيك المفتاح: ghp_abcdefghijklmnopqrstu", "critical"),
    ("هذا هو الـ API Key تبعي: sk-abc123", "critical"),
    ("token للمشروع: eyJhbGciOiJSUzI1NiJ9.abc", "critical"),
    ("مفتاح التطبيق: AIzaSyAbCdEfGhIjKlMn", "critical"),
    ("هذا access token: ya29.xyzabcdef123456", "critical"),
    ("رمز المصادقة: Bearer eyJhbGc.abc.xyz", "critical"),
    ("stripe key: sk_live_newkey123456789abcdef", "critical"),
    ("app_secret=MyAppNewSecret2024!", "critical"),
    ("jwt_secret=NewJwtSecret@2024Secure", "critical"),
    # ── مفاتيح تشفير خاصة ──
    ("-----BEGIN RSA PRIVATE KEY-----", "critical"),
    ("-----BEGIN PRIVATE KEY-----", "critical"),
    ("private_key=-----BEGIN EC PRIVATE KEY-----", "critical"),
    ("private ssh key: -----BEGIN OPENSSH PRIVATE KEY-----", "critical"),
    ("pgp private key: -----BEGIN PGP PRIVATE KEY BLOCK-----", "critical"),
    ("private_key = MIIEvgIBADANBgkqhkiG9w0B", "critical"),
    ("seed phrase: apple banana cherry dog elephant fox", "critical"),
    ("metamask seed: abandon ability able about above absent", "critical"),
    ("private key للمحفظة: 5KJvsngHeMpm884wtkJNzQGaCErckhHJ", "critical"),
    # ── أكواد OTP والرموز السرية ──
    ("رمز الـ OTP السري: 847291", "critical"),
    ("كود التحقق: 293847", "critical"),
    ("one time password: 582930", "critical"),
    ("verification code: 748291", "critical"),
    ("pin code: 9284 للبطاقة", "critical"),
    ("الرقم السري للبطاقة: 4829", "critical"),
    ("security question answer: اسم حيواني الأليف قطو", "critical"),
    ("secret answer: اسم أمي فاطمة", "critical"),
    # ================================================================
    # 🔴 HIGH — بيانات شخصية تنتهك الخصوصية
    # ================================================================
    # ── هوية + معلومات تعريفية ──
    ("اسمي أحمد ورقم هويتي 123456789 وعنواني رام الله", "high"),
    ("رقم هويتي 987654321", "high"),
    ("my id number is 456789123", "high"),
    ("passport number: AB1234567", "high"),
    ("رقم جواز سفري A12345678", "high"),
    ("national id: 1234567890", "high"),
    ("رقم الهوية الوطنية 9876543210", "high"),
    ("SSN: 123-45-6789", "high"),
    ("social security number 987654321", "high"),
    ("رقم الإقامة 2345678901", "high"),
    ("id card number: 0987654321", "high"),
    ("citizen id: 1122334455", "high"),
    ("رقم هويتي الوطنية 123-456-789", "high"),
    ("my national ID is 9876543210", "high"),
    ("رقم بطاقة الهوية: 1234567890", "high"),
    ("identity number: 0987654321", "high"),
    ("رقم الجواز: PA9876543", "high"),
    ("passport no: BC1234567", "high"),
    # ── إيميل + سياق تعريفي ──
    ("تواصل معي على ahmed@company.com ورقم هويتي 123456", "high"),
    ("اسمي أحمد وبريدي ahmed@company.com وأسكن رام الله", "high"),
    ("اسم المريض: أحمد، الإيميل: ahmed@hospital.ps", "high"),
    ("الموظف محمد، بريده: mohammed@company.com، هاتفه: 0591234567", "high"),
    ("full name: Sarah Johnson, email: sarah@company.com, dob: 1990-01-15", "high"),
    ("patient info: name: Ahmed, email: ahmed@clinic.ps, condition: diabetes", "high"),
    ("staff record: Omar Ali, email: omar@school.edu, id: 1234567890", "high"),
    # ── هاتف + سياق تعريفي ──
    ("اسمي محمد ورقم هاتفي 0591234567 وأسكن في نابلس", "high"),
    ("رقم هاتفي 0599887766 وعنواني شارع النزهة", "high"),
    ("contact: Ahmed Al-Masri, phone: +970591234567, address: Ramallah", "high"),
    ("العميل: فاطمة علي، الهاتف: 0592345678، العنوان: غزة", "high"),
    # ── عناوين سكن تفصيلية ──
    ("عنواني: شارع النزهة، رام الله، فلسطين", "high"),
    ("my address is 123 Main Street, New York, NY 10001", "high"),
    ("أسكن في حي الرشيد، شارع 5، بيت رقم 12، نابلس", "high"),
    ("home address: 456 Oak Avenue, London, SW1A 1AA", "high"),
    ("العنوان: مخيم بلاطة، نابلس، فلسطين", "high"),
    ("عنوان السكن: حي الزيتون، غزة، شارع 10، بناء 3", "high"),
    ("أسكن في: شارع صلاح الدين، القدس، شقة 5", "high"),
    ("living at: 321 Elm Street, Apt 4B, Toronto, ON", "high"),
    ("address: Flat 5, Building 3, Al-Bireh, Ramallah", "high"),
    # ── معلومات طبية شخصية ──
    ("اسم المريض أحمد، تشخيصه: داء السكري من النوع الثاني", "high"),
    ("patient Ahmed Ali, diagnosis: hypertension, medication: metformin", "high"),
    ("السجل الطبي: فاطمة، تأخذ دواء: ميتفورمين 850 ملغ يومياً", "high"),
    ("medical record: Sarah, condition: HIV positive, treatment: ART", "high"),
    ("رقم المريض: MRN-123456، الحالة: سرطان، العلاج: كيماوي", "high"),
    ("تشخيصي: داء السكري من النوع الثاني، دوائي: ميتفورمين", "high"),
    ("my diagnosis is hypertension, taking lisinopril 10mg daily", "high"),
    ("medical record number: MRN-123456, condition: diabetes type 2", "high"),
    ("insurance policy: POL-987654321, covered condition: cancer", "high"),
    ("blood type: O negative, patient: Ahmed, id: 123456", "high"),
    # ── تاريخ ميلاد + معلومات ──
    ("تاريخ ميلادي 15/03/1995 ورقم هويتي 123456789", "high"),
    ("date of birth: 1990-07-22, passport: AB1234567", "high"),
    ("DOB: 1995-12-15, SSN: 123-45-6789", "high"),
    ("born on January 5, 1988, national ID: 987654321", "high"),
    ("تاريخ الميلاد: 1998/05/20، رقم الهوية: 1234567890", "high"),
    # ── اسم + معلومات حساسة ──
    ("اسمي أحمد محمود ورقم هاتفي 0591234567", "high"),
    ("my name is Sarah Johnson and my SSN is 123-45-6789", "high"),
    ("الاسم الكامل: محمد أحمد الخليل، رقم الهوية: 123456789", "high"),
    ("full name: Sarah Elizabeth Johnson, DOB: 1990-01-15, ID: 987654321", "high"),
    ("اسم الأم: فاطمة محمود، رقم هويتها: 987654321", "high"),
    ("mother's maiden name: Johnson, SSN: 123-45-6789", "high"),
    # ── حسابات بنكية ──
    ("حسابي البنكي رقم 123456789", "high"),
    ("bank account number: 9876543210", "high"),
    ("رقم الحساب البنكي: 1234567890", "high"),
    ("my bank account is 0987654321", "high"),
    ("رقم حسابي في البنك: 2345678901", "high"),
    ("transfer to account number 6789012345", "high"),
    ("رقم الحساب للتحويل: 7890123456", "high"),
    ("bank account: 3456789012 routing: 021000021", "high"),
    ("الحساب البنكي رقم 4567890123 في بنك فلسطين", "high"),
    # ── IP داخلية ──
    ("السيرفر الداخلي على 192.168.1.100", "high"),
    ("internal ip: 10.0.0.5", "high"),
    ("server ip address: 172.16.0.1", "high"),
    ("عنوان السيرفر الداخلي: 192.168.0.50", "high"),
    ("production server: 10.10.10.1", "high"),
    ("internal network: 172.31.255.255", "high"),
    ("ip السيرفر الداخلي: 192.168.10.50", "high"),
    ("database server: 192.168.0.100", "high"),
    ("شبكة داخلية: 172.16.10.5", "high"),
    ("network camera ip: 10.0.0.200", "high"),
    # ================================================================
    # 🟠 MEDIUM — حساسة لكن وحدها لا تكفي للاحتيال
    # ================================================================
    # ── إيميل مجرد (بدون سياق تعريفي) ──
    ("تواصل معي على ahmed@company.com", "medium"),
    ("email: support@hospital.ps", "medium"),
    ("بريدي الإلكتروني: user@gmail.com", "medium"),
    ("my email is john.doe@example.com", "medium"),
    ("send to: admin@internal.company.org", "medium"),
    ("contact: info@mybusiness.net", "medium"),
    ("راسلني على: tala@university.edu", "medium"),
    ("email address: boss@corp.co.uk", "medium"),
    ("البريد الإلكتروني: sales@store.ps", "medium"),
    ("reach me at developer@startup.io", "medium"),
    ("ايميلي هو: mohammed@hotmail.com", "medium"),
    ("my work email: sarah.johnson@bigcorp.com", "medium"),
    ("الإيميل الرسمي: official@ministry.gov.ps", "medium"),
    ("بريد العمل: hr@organization.org", "medium"),
    # ── هاتف مجرد ──
    ("رقم هاتفي 0591234567", "medium"),
    ("call me on 0599887766", "medium"),
    ("my phone number is +1-555-123-4567", "medium"),
    ("رقم جوالي: 00970599123456", "medium"),
    ("mobile: +44 7911 123456", "medium"),
    ("tel: 0501234567", "medium"),
    ("اتصل بي على 0521234567", "medium"),
    ("phone: +962791234567", "medium"),
    ("رقم الموبايل 0591234567", "medium"),
    ("رقم الجوال: 0592345678", "medium"),
    ("رقم واتساب: 00970592345678", "medium"),
    ("my cell: +1-800-555-0123", "medium"),
    # ── معلومات مالية عامة ──
    ("راتبي الشهري 5000 دينار", "medium"),
    ("my monthly salary is $8000", "medium"),
    ("annual salary: $95,000", "medium"),
    ("monthly income: 3500 JD", "medium"),
    ("دخلي الشهري 8000 شيكل", "medium"),
    ("IBAN: PS92PALS000000000400123456702", "medium"),
    ("account balance: $15,432.50", "medium"),
    ("رصيد حسابي 25000 شيكل", "medium"),
    ("invoice total: $2,500 USD", "medium"),
    ("routing number: 021000021", "medium"),
    ("swift code: CITIUS33", "medium"),
    ("رقم الشيك: 001234", "medium"),
    ("credit score: 750", "medium"),
    ("tax ID: 123-45-6789", "medium"),
    ("vat number: PS123456789", "medium"),
    # ── روابط قواعد بيانات ──
    ("mongodb://admin:pass@localhost:27017/mydb", "medium"),
    ("mysql://root:password@192.168.1.1/users", "medium"),
    ("postgresql://user:pass@db.internal:5432", "medium"),
    ("redis://localhost:6379", "medium"),
    ("sqlite:///app.db connection string", "medium"),
    ("mongodb+srv://user:pass@cluster.mongodb.net/db", "medium"),
    ("DATABASE_URL=postgres://user:pass@host:5432/db", "medium"),
    ("mysql://admin:secret@db.server.com/production", "medium"),
    ("MONGO_URI=mongodb://root:example@mongo:27017", "medium"),
    ("cassandra://user:pass@localhost:9042/keyspace", "medium"),
    ("elasticsearch://admin:secret@localhost:9200", "medium"),
    ("REDIS_URL=redis://localhost:6379/0", "medium"),
    ("RABBITMQ_URL=amqp://user:pass@rabbitmq:5672", "medium"),
    ("connection: host=localhost port=5432 dbname=mydb", "medium"),
    ("DB_HOST=db.internal.company.com", "medium"),
    ("DATABASE_HOST=postgres.internal:5432", "medium"),
    # ── بورتات وسيرفرات ──
    ("الاتصال بـ localhost:8080", "medium"),
    ("server at 127.0.0.1:3000", "medium"),
    ("running on port 8443", "medium"),
    ("backend server: localhost:5000", "medium"),
    ("السيرفر على البورت 3306", "medium"),
    ("app running at 0.0.0.0:8000", "medium"),
    ("debug port: 9229", "medium"),
    ("nginx running on port 80 and 443", "medium"),
    ("السيرفر يعمل على: 0.0.0.0:3000", "medium"),
    ("websocket server: ws://localhost:8765", "medium"),
    ("dev server running at localhost:4200", "medium"),
    ("api gateway: localhost:8000", "medium"),
    ("smtp server: mail.company.com:587", "medium"),
    ("imap server: imap.gmail.com:993", "medium"),
    ("ftp server: ftp.mysite.com port 21", "medium"),
    # ── معلومات طبية عامة (بدون اسم) ──
    ("blood pressure: 120/80", "medium"),
    ("ضغط الدم: 130/85", "medium"),
    ("sugar level: 110 mg/dL", "medium"),
    ("مستوى السكر في الدم: 95", "medium"),
    ("cholesterol: 180 mg/dL", "medium"),
    ("allergy to: penicillin", "medium"),
    ("taking medication: metformin 500mg", "medium"),
    ("prescription: amoxicillin 500mg twice daily", "medium"),
    ("vaccination record: COVID-19 Pfizer 2 doses", "medium"),
    ("الحالة الصحية: ضغط دم مرتفع", "medium"),
    ("medical condition: type 1 diabetes", "medium"),
    ("lab results: hemoglobin 13.5", "medium"),
    ("heart rate: 72 bpm", "medium"),
    # ================================================================
    # 🟢 SAFE — آمن تماماً
    # ================================================================
    # ── كود برمجي — حتى لو فيه كلمة password! ──
    # القاعدة: الكود للتعلم أو التطوير = آمن
    ("const password = '***'; // placeholder", "safe"),
    ("input type='password' placeholder='Enter password'", "safe"),
    ("function login(username, password) { return auth(username, password); }", "safe"),
    ("if (password.length < 8) throw new Error('weak password')", "safe"),
    ("password_field = document.getElementById('password')", "safe"),
    ("hash = bcrypt.hash(password, 10)", "safe"),
    ("// TODO: validate password strength", "safe"),
    ("<!-- <input type='password'> -->", "safe"),
    ("def check_password(stored_hash, input_password):", "safe"),
    ("password_policy = {'min_length': 8, 'require_uppercase': True}", "safe"),
    ("print('Enter your password: ')", "safe"),
    ("class PasswordValidator: pass", "safe"),
    ("token = jwt.encode(payload, secret, algorithm='HS256')", "safe"),
    ("api_key = os.getenv('API_KEY')  # loaded from env", "safe"),
    ("config['api_key'] = '${API_KEY}'  # from environment", "safe"),
    ("SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback')", "safe"),
    ("your_api_key = 'YOUR_API_KEY_HERE'  # replace this", "safe"),
    ("email = models.EmailField()  # django model field", "safe"),
    ("phone = PhoneField(required=False)", "safe"),
    ("class UserProfile(models.Model): email = EmailField()", "safe"),
    ("def send_email(to_address, subject, body): pass", "safe"),
    ("SELECT * FROM users WHERE email = ?", "safe"),
    ("ALTER TABLE users ADD COLUMN phone VARCHAR(20)", "safe"),
    ("CREATE INDEX idx_email ON users(email)", "safe"),
    ("# Example: password=your_password_here", "safe"),
    ("## Configuration\napi_key: <your-api-key>", "safe"),
    ("Replace YOUR_TOKEN with your actual token", "safe"),
    ("$email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);", "safe"),
    ("router.post('/login', authController.login);", "safe"),
    ("<form action='/login' method='post'>", "safe"),
    # ── برمجة وتقنية عامة ──
    ("كيف أكتب حلقة for في Python؟", "safe"),
    ("ما هو الذكاء الاصطناعي؟", "safe"),
    ("شرح لي كيف أعمل موقع ويب", "safe"),
    ("what is machine learning?", "safe"),
    ("how to center a div in css", "safe"),
    ("اشرح لي مفهوم الـ API", "safe"),
    ("ما الفرق بين React و Vue؟", "safe"),
    ("help me write a python function", "safe"),
    ("كيف أتعلم البرمجة من الصفر؟", "safe"),
    ("what are the best practices for coding?", "safe"),
    ("how do I use async await in JavaScript?", "safe"),
    ("explain the difference between SQL and NoSQL", "safe"),
    ("كيف أعمل deploy للموقع؟", "safe"),
    ("what is the time complexity of quicksort?", "safe"),
    ("اشرح لي مفهوم الـ recursion", "safe"),
    ("how to use git branches?", "safe"),
    ("ما هو الفرق بين HTTP و HTTPS؟", "safe"),
    ("explain REST API design principles", "safe"),
    ("كيف أستخدم Docker؟", "safe"),
    ("what is a binary search tree?", "safe"),
    ("how to optimize database queries?", "safe"),
    ("اشرح لي مفهوم الـ microservices", "safe"),
    ("what is CI/CD pipeline?", "safe"),
    ("كيف أعمل unit testing؟", "safe"),
    ("explain object oriented programming", "safe"),
    ("ما هو الفرق بين == و === في JavaScript؟", "safe"),
    ("كيف أعمل pagination بالـ API؟", "safe"),
    ("explain the concept of closures in JavaScript", "safe"),
    ("ما هو الـ promise وكيف يعمل؟", "safe"),
    ("how to handle errors in Python?", "safe"),
    ("اشرح لي مفهوم الـ middleware", "safe"),
    ("what is the difference between PUT and PATCH?", "safe"),
    ("كيف أعمل authentication بالـ JWT؟", "safe"),
    ("how to use redux for state management?", "safe"),
    ("اشرح لي مفهوم الـ virtual DOM", "safe"),
    ("what is webpack and how does it work?", "safe"),
    ("explain SOLID principles in OOP", "safe"),
    ("how to implement a linked list in Python?", "safe"),
    ("اشرح خوارزمية الـ bubble sort", "safe"),
    ("explain how CORS works", "safe"),
    ("ما هو الفرق بين REST و GraphQL؟", "safe"),
    ("how to write clean code?", "safe"),
    ("explain agile methodology", "safe"),
    ("how to use TypeScript with React?", "safe"),
    ("اشرح لي مفهوم الـ serverless", "safe"),
    ("كيف تعمل الـ blockchain؟", "safe"),
    # ── أسئلة AI ──
    ("what is the difference between GPT-3 and GPT-4?", "safe"),
    ("كيف يعمل نموذج الـ diffusion للصور؟", "safe"),
    ("explain attention mechanism in transformers", "safe"),
    ("ما هو الـ fine-tuning للنماذج؟", "safe"),
    ("how does DALL-E generate images?", "safe"),
    ("اشرح لي مفهوم الـ embedding", "safe"),
    ("what is retrieval augmented generation?", "safe"),
    ("كيف أعمل chatbot بسيط؟", "safe"),
    ("explain the difference between AI and automation", "safe"),
    ("ما هي أخلاقيات الذكاء الاصطناعي؟", "safe"),
    ("ما هو ChatGPT؟", "safe"),
    ("كيف يعمل نموذج اللغة؟", "safe"),
    ("what are the benefits of AI?", "safe"),
    ("اشرح لي مفهوم الـ neural network", "safe"),
    ("how does image recognition work?", "safe"),
    ("ما هو الفرق بين AI و ML؟", "safe"),
    ("explain transformer architecture", "safe"),
    ("كيف أدرب نموذج AI؟", "safe"),
    ("what is natural language processing?", "safe"),
    ("اشرح لي مفهوم الـ deep learning", "safe"),
    # ── أسماء مجردة (بدون معلومات حساسة) ──
    ("اسمي محمد وأنا مبرمج", "safe"),
    ("اسمي سارة وأحب القراءة", "safe"),
    ("اسمي تالا", "safe"),
    ("my name is John", "safe"),
    ("my name is Sarah and I love coding", "safe"),
    ("اسمي خالد وأنا من نابلس", "safe"),
    ("my name is Omar and I live in Ramallah", "safe"),
    ("اسمي فاطمة وأدرس هندسة", "safe"),
    ("اسم الأب: محمد علي", "safe"),
    ("father name: Abdullah Hassan", "safe"),
    ("اسم العائلة: الصفدي", "safe"),
    ("family name: Al-Masri", "safe"),
    ("الاسم الثلاثي: أحمد محمود سالم", "safe"),
    # ── وصف جسدي عام ──
    ("وزني 85 كيلو وطولي 175 سم", "safe"),
    ("my height is 180cm and weight is 75kg", "safe"),
    ("أنا طولي 165 وبدي أنزل وزن", "safe"),
    ("BMI calculator: weight / height^2", "safe"),
    # ── محادثات عامة ──
    ("كيف حالك", "safe"),
    ("كيف الحال", "safe"),
    ("صباح الخير", "safe"),
    ("مساء الخير", "safe"),
    ("how are you?", "safe"),
    ("good morning", "safe"),
    ("what's up?", "safe"),
    ("أهلاً وسهلاً", "safe"),
    ("شو الأخبار", "safe"),
    ("تمام بخير شكراً", "safe"),
    ("مرحباً ، كيفك الاخبار", "safe"),
    ("بعتت لصحبيتي الرسالة امبارح", "safe"),
    ("hello how are you today?", "safe"),
    ("I'm doing great thanks!", "safe"),
    ("شكراً جزيلاً على مساعدتك", "safe"),
    # ── تعليم وحياة عامة ──
    ("اكتب لي قصيدة عن فلسطين", "safe"),
    ("summarize this article for me", "safe"),
    ("translate this text to english", "safe"),
    ("كيف أحسّن أداء موقعي؟", "safe"),
    ("explain recursion with examples", "safe"),
    ("what is the capital of France?", "safe"),
    ("كيف أطبخ المنسف؟", "safe"),
    ("ما هي أفضل كتب البرمجة؟", "safe"),
    ("write a story about a robot", "safe"),
    ("explain photosynthesis simply", "safe"),
    ("ما هو تاريخ القدس؟", "safe"),
    ("how does the internet work?", "safe"),
    ("اشرح لي نظرية النسبية", "safe"),
    ("what causes climate change?", "safe"),
    ("كيف أتعلم اللغة الإنجليزية؟", "safe"),
    ("help me plan a road trip", "safe"),
    ("write a cover letter for me", "safe"),
    ("ما هي فوائد التمر؟", "safe"),
    ("how to meditate for beginners?", "safe"),
    ("اشرح لي كيف تعمل الطائرات", "safe"),
    ("كيف أنظم وقتي بشكل أفضل؟", "safe"),
    ("what are good habits for productivity?", "safe"),
    ("اقترح لي كتب للقراءة", "safe"),
    ("how to learn a new language quickly?", "safe"),
    ("help me write a birthday message", "safe"),
    ("كيف أحضّر لمقابلة عمل؟", "safe"),
    ("what questions should I ask in a job interview?", "safe"),
    ("اكتب لي CV احترافي", "safe"),
    ("how to start a small business?", "safe"),
    ("أنا أدرس هندسة البرمجيات", "safe"),
    ("I am a software engineering student", "safe"),
    ("أعمل مطور ويب منذ 3 سنوات", "safe"),
    ("I work as a frontend developer", "safe"),
    ("أحب البرمجة وتطوير التطبيقات", "safe"),
    ("I enjoy coding and building apps", "safe"),
    ("أنا في سنتي الثالثة بالجامعة", "safe"),
    ("I am studying computer science", "safe"),
    ("هل الذكاء الاصطناعي سيأخذ وظيفتي؟", "safe"),
    ("will AI replace programmers?", "safe"),
    ("ما مستقبل تطوير الويب؟", "safe"),
    ("what are the trends in software development?", "safe"),
    ("اشرح لي مفهوم الـ open source", "safe"),
    ("what is the difference between Linux and Windows?", "safe"),
    ("what IDE should I use for Python?", "safe"),
    ("how to set up a development environment?", "safe"),
]

# ================================================================
# التحقق من التوازن
# ================================================================
texts = [row[0] for row in data]
labels = [row[1] for row in data]

print(f"✅ البيانات: {len(texts)} جملة")
print(f"   التصنيفات: {set(labels)}")
for label in ["critical", "high", "medium", "safe"]:
    count = labels.count(label)
    print(f"   {label:8}: {count} جملة")

# ================================================================
# المرحلة 2 — تحويل النص لأرقام
# ================================================================
vectorizer = TfidfVectorizer(
    analyzer="char_wb",
    ngram_range=(2, 5),  # زدنا لـ 5 عشان يلتقط أنماط أطول
    max_features=15000,  # زدنا عشان البيانات أكثر تنوعاً
    sublinear_tf=True,
    min_df=1,  # نأخذ كل الأنماط حتى النادرة
)

X = vectorizer.fit_transform(texts)
print(f"\n✅ تحويل النص: كل جملة صارت {X.shape[1]} رقم")

# ================================================================
# المرحلة 3 — تقسيم البيانات
# ================================================================
X_train, X_test, y_train, y_test = train_test_split(
    X, labels, test_size=0.2, random_state=42, stratify=labels
)

print(f"\n✅ تقسيم البيانات:")
print(f"   التدريب: {X_train.shape[0]} جملة")
print(f"   الاختبار: {X_test.shape[0]} جملة")

# ================================================================
# المرحلة 4 — تدريب النموذج
# ================================================================
model = RandomForestClassifier(
    n_estimators=500,  # زدنا من 300 لـ 500
    max_depth=None,
    min_samples_leaf=1,  # مهم للبيانات المتنوعة
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",  # يعامل التصنيفات بالتساوي حتى لو أعدادها مختلفة
)

print("\n⏳ جاري التدريب...")
model.fit(X_train, y_train)
print("✅ التدريب اكتمل!")

# ================================================================
# المرحلة 5 — اختبار الدقة
# ================================================================
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n📊 نتائج الاختبار:")
print(f"   الدقة الكلية: {accuracy * 100:.1f}%")
print("\n📋 تقرير تفصيلي:")
print(classification_report(y_test, y_pred, zero_division=0))

# ================================================================
# المرحلة 6 — حفظ النموذج
# ================================================================
os.makedirs("models", exist_ok=True)

joblib.dump(model, "models/classifier.pkl")
joblib.dump(vectorizer, "models/vectorizer.pkl")

print("✅ النموذج محفوظ في models/")

# ================================================================
# اختبار سريع — يشمل حالات صعبة
# ================================================================
print("\n🧪 اختبار سريع:")
test_cases = [
    # critical — واضحة
    ("رقم بطاقتي 4532015112830366", "critical"),
    ("password=Admin123", "critical"),
    ("api_key=sk-abc123def456ghi789jkl", "critical"),
    # critical — صعبة (كود + password)
    ("كلمة المرور : Admin2024", "critical"),
    ("my wifi password is SuperSecret99", "critical"),
    # safe — كود فيه password (الأهم!)
    ("const password = '***';", "safe"),
    ("input type='password'", "safe"),
    ("function login(u, password) { }", "safe"),
    ("# Example: password=your_password", "safe"),
    # high — مع سياق
    ("اسمي أحمد ورقم هاتفي 0591234567", "high"),
    ("my name is Sarah, SSN: 123-45-6789", "high"),
    ("تشخيصي: السكري، دوائي: ميتفورمين", "high"),
    # medium — مجرد
    ("تواصل معي على ahmed@company.com", "medium"),
    ("رقم هاتفي 0591234567", "medium"),
    ("راتبي الشهري 5000 دينار", "medium"),
    ("mongodb://root:pass@localhost:27017", "medium"),
    # safe — عادي
    ("كيف أكتب حلقة for؟", "safe"),
    ("what is machine learning?", "safe"),
    ("اسمي تالا", "safe"),
    ("صباح الخير", "safe"),
]

correct = 0
for text, expected in test_cases:
    X_new = vectorizer.transform([text])
    pred = model.predict(X_new)[0]
    prob = max(model.predict_proba(X_new)[0]) * 100
    icon = "🔴" if pred in ["critical", "high"] else "🟠" if pred == "medium" else "🟢"
    check = "✅" if pred == expected else "❌"
    correct += 1 if pred == expected else 0
    print(f"   {check} {icon} [{pred:8}] {prob:.0f}% ← {text[:50]}")

print(
    f"\n📊 دقة الاختبار السريع: {correct}/{len(test_cases)} ({correct/len(test_cases)*100:.0f}%)"
)
