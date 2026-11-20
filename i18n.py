"""
TBD Internationalization (i18n) Engine
Provides native, expressive, non-literal Arabic and English localization.
"""

STRINGS = {
    "en": {
        "app_title": "TBD",
        "app_subtitle": "Autonomous Zero-Day & Ransomware Endpoint Defense",
        "admin_active": "● Administrator Privileges Active (Maximum Defense)",
        "admin_limited": "● User Mode (Run as Admin for network isolation)",
        "status_secure": "PROTECTION: ACTIVE & SYSTEM SECURE",
        "status_threat": "ALERT: THREAT DETECTED & NEUTRALIZED",
        "status_isolated": "EMERGENCY: SYSTEM ISOLATED (AIR-GAPPED)",
        
        # Tabs
        "tab_dashboard": "🛡️ Security Dashboard",
        "tab_scanner": "🔍 File Scanner",
        "tab_processes": "⚡ Active Processes",
        "tab_logs": "📋 Event Logs",
        "tab_quarantine": "🔒 Quarantine Vault",
        "tab_settings": "⚙️ Settings",
        
        # Dashboard KPIs
        "kpi_threats": "THREATS BLOCKED",
        "kpi_canaries": "CANARY DECOYS",
        "kpi_canaries_val": "4 Folders Protected",
        "kpi_processes": "PROCESSES MONITORERED",
        "kpi_quarantine": "QUARANTINED FILES",
        
        # Shields
        "shields_title": "REAL-TIME ACTIVE DEFENSE SHIELDS",
        "sh_behavioral_title": "Behavioral Anomaly & LOLBins Defense",
        "sh_behavioral_desc": "Monitors running programs to block zero-day exploits, memory injections, and hidden malicious scripts.",
        "sh_ransomware_title": "Zero-Day Ransomware Decoy Traps",
        "sh_ransomware_desc": "Plants smart decoy files in key folders to catch and terminate ransomware instantly before user files can be touched.",
        "sh_network_title": "Outbound Network & Reverse Shell Watchdog",
        "sh_network_desc": "Prevents unauthorized outbound connections, data theft, and remote hacker command & control (C2) channels.",
        "sh_persistence_title": "Startup & Registry Auto-Run Guard",
        "sh_persistence_desc": "Guards Windows startup and registry against stealthy trojans attempting to launch automatically on reboot.",
        
        # Actions
        "actions_title": "AUTONOMOUS AIR-GAP & RESCUE CONTROLS",
        "btn_isolate": "🚨 Emergency Air-Gap (Isolate Host)",
        "btn_restore": "🔄 Restore Network Connectivity",
        "btn_refresh_canaries": "🛡️ Refresh Decoy Canaries",
        
        # Scanner Tab
        "scan_placeholder": "Select a file to inspect for zero-day threats, packed code, and ransomware signatures...",
        "btn_browse": "📁 Browse File",
        "btn_scan": "⚡ Deep Scan",
        "scan_ready": "READY TO SCAN",
        "btn_quarantine_scan": "🔒 Quarantine Threat Immediately",
        
        # Process Tab
        "proc_title": "RUNNING PROCESSES & BEHAVIORAL RISK RATINGS",
        "btn_refresh_proc": "🔄 Refresh Process List",
        
        # Logs Tab
        "logs_title": "REAL-TIME SECURITY AUDIT LOGS",
        "btn_clear_logs": "🧹 Clear Logs",
        
        # Quarantine Tab
        "quarantine_title": "NEUTRALIZED THREATS (XOR ENCRYPTED VAULT)",
        "btn_refresh_vault": "🔄 Refresh Vault",
        
        # Settings Tab
        "settings_title": "TBD PREFERENCES & SYSTEM CONFIGURATION",
        "settings_section_general": "General & Startup",
        "settings_autostart": "Launch TBD automatically when Windows boots",
        "settings_autostart_desc": "Keep the system protected from the very moment the computer turns on.",
        "settings_language": "Display Language",
        "settings_theme": "Visual Theme",
        "theme_dark": "Dark Theme (Cybersecurity)",
        "theme_light": "Light Theme",
        "theme_system": "System Default",
        
        "settings_section_defense": "Autonomous Defense Behavior",
        "settings_autokill": "Automatically terminate and quarantine detected threats",
        "settings_autokill_desc": "When enabled, malicious processes and zero-day encryptors are halted immediately without delay.",
        "settings_sensitivity": "Heuristic Scanning Sensitivity",
        "sens_normal": "Normal - Recommended for standard everyday use",
        "sens_high": "High - Strict inspection of unknown or untrusted scripts",
        "sens_strict": "Strict - Maximum scrutiny (ideal for high-risk environments)",
        
        "settings_section_canary": "Ransomware Decoy Trap Locations",
        "canary_desktop": "Protect Desktop folder",
        "canary_documents": "Protect Documents folder",
        "canary_downloads": "Protect Downloads folder",
        "canary_pictures": "Protect Pictures folder",
        
        "btn_save_settings": "💾 Save Settings",
        "btn_reset_settings": "↺ Reset to Defaults",
        "settings_saved_msg": "Settings have been successfully updated and saved.",
        "settings_reset_msg": "Settings have been reset to factory defaults.",
        
        # Dialogs
        "confirm_isolation_title": "Confirm Host Isolation",
        "confirm_isolation_msg": "Are you sure you want to cut off all network connectivity?\n\nThis will disable network adapters to contain an active infection.",
        "isolation_success": "System network adapters successfully disabled and IP released.",
        "restore_success": "Network adapters re-enabled and IP address renewed successfully.",

        # Demo Suite Strings
        "demo_title": "🚨 TBD Live Threat Simulator (ISEF Judge Presentation)",
        "demo_subtitle": "Safe & controlled live testing platform for ISEF judge demonstrations • 100% safe simulation",
        "demo_status_ready": "Status: Ready for judge presentation. Make sure TBD is running side-by-side with this window.",
        "demo_btn_cleanup": "🧹 Clean Up Test Artifacts",
        "demo_badge_prefix": "Test #",

        "demo1_title": "Simulate Zero-Day Ransomware Encryption Attempt",
        "demo1_desc": "This button simulates ransomware attempting to encrypt user files on the Desktop with high entropy (7.8/8.0). Watch the TBD screen immediately to see how it detects the encryption attempt and kills the process in under half a second!",
        "demo1_btn": "💥 Launch Ransomware Test Attack",
        "demo1_running": "Simulating ransomware attack... Watch the TBD screen now!",
        "demo1_dialog_title": "Simulation Launched",
        "demo1_dialog_msg": "Successfully simulated canary file encryption attempt!\nFile: {}\n\nWatch the TBD screen: you'll see a red alert showing real-time encryption detection and attack termination!",
        "demo1_done": "Ransomware simulation complete! Check for the red alert in TBD.",

        "demo2_title": "Simulate Living-Off-The-Land (PowerShell / VSSAdmin)",
        "demo2_desc": "Launches a hidden, Base64-obfuscated PowerShell script and attempts to invoke backup-deleting commands. Watch TBD detect the process, classify it as high-risk, and terminate it immediately.",
        "demo2_btn": "⚡ Launch Hidden Exploit Script",
        "demo2_running": "Launching hidden LOLBin script...",
        "demo2_dialog_title": "Script Launched",
        "demo2_dialog_msg": "A hidden, Base64-obfuscated PowerShell command has been launched!\n\nCheck the Event Logs or Active Processes tab in TBD to see how it detects the behavioral camouflage and assigns a high risk score!",
        "demo2_done": "LOLBin script launched. Check TBD event logs.",

        "demo3_title": "Simulate Outbound Backdoor Connection (Port 4444)",
        "demo3_desc": "Attempts to open a suspicious outbound connection on port 4444, famously used by spyware. Watch TBD's Network Sentinel detect the suspicious port and immediately close the connection to protect the system.",
        "demo3_btn": "🌐 Launch Outbound Spy Connection",
        "demo3_running": "Attempting suspicious outbound connection on port 4444...",
        "demo3_dialog_title": "Connection Attempted",
        "demo3_dialog_msg": "An outbound connection attempt on port 4444 (known Metasploit Reverse Shell port) has been made.\n\nTBD's Network Sentinel is scanning and containing any unauthorized outbound connection.",
        "demo3_done": "Port 4444 connection checked in TBD.",

        "demo4_title": "Simulate Auto-Run Registry Key Injection",
        "demo4_desc": "Attempts to inject a new key into the Windows Registry (Run Key) to auto-launch on boot. TBD's Persistence Guard detects the registry change and fires an immediate security alert in the logs.",
        "demo4_btn": "📌 Inject Auto-Start Registry Key",
        "demo4_running": "Attempting to inject a startup registry key...",
        "demo4_dialog_title": "Registry Key Injected",
        "demo4_dialog_msg": "A test auto-run key named 'TBD_Judge_Demo_Persistence' has been added.\n\nTBD's Persistence Guard will detect the change and fire it as a registry breach alert in the Event Logs!",
        "demo4_done": "Registry key injected! Check TBD event logs.",

        "demo5_title": "Generate Mock Packed Malware Sample on Desktop",
        "demo5_desc": "Creates a fake file on the Desktop with encryption characteristics and suspicious content, so you can ask the judges to scan it in TBD's File Scanner tab and see the section analysis, entropy, and quarantine button.",
        "demo5_btn": "📁 Generate Test Sample on Desktop",
        "demo5_running": "Generating mock malware sample...",
        "demo5_dialog_title": "Sample Created Successfully",
        "demo5_dialog_msg": "A test sample file has been created on the Desktop:\n{}\n\nNext steps for judges:\n1. Open the 'File Scanner' tab in TBD.\n2. Select this file and click 'Deep Scan'.\n3. TBD will show high entropy (7.8/8.0), classify it as malicious (100/100), and offer to quarantine it!",
        "demo5_done": "Sample created: {} on Desktop.",

        "demo_cleanup_title": "Cleanup Complete",
        "demo_cleanup_msg": "Cleaned up: {}",
        "demo_cleanup_none": "No test artifacts found",
        "demo_cleanup_regkey": "Test registry key",
        "demo_cleanup_sample": "Sample file from Desktop",

        "demo_error": "Error",
        "demo_error_msg": "Could not execute simulation: {}"
    },
    
    "ar": {
        "app_title": "TBD",
        "app_subtitle": "منظومة الدفاع الاستباقي والحماية من فيروسات الفدية وهجمات الـ Zero-Day",
        "admin_active": "● صلاحيات الأدمن مفعلة (حماية قصوى وصلاحيات عزل كاملة)",
        "admin_limited": "● وضع مستخدم عادي (شغل البرنامج كمسؤول للحصول على صلاحيات عزل الشبكة)",
        "status_secure": "حالة الحماية: الجهاز آمن ومحمي بالكامل",
        "status_threat": "تنبيه: تم رصد تهديد خطير وإيقافه بنجاح",
        "status_isolated": "حالة الطوارئ: تم عزل الجهاز وفصل الإنترنت لمنع انتشار الهجوم",
        
        # Tabs
        "tab_dashboard": "🛡️ لوحة الحماية والتحكم",
        "tab_scanner": "🔍 فحص الملفات المتقدم",
        "tab_processes": "⚡ البرامج والعمليات النشطة",
        "tab_logs": "📋 سجل الأحداث والتنبيهات",
        "tab_quarantine": "🔒 قبو العزل للملفات المشبوهة",
        "tab_settings": "⚙️ إعدادات البرنامج",
        
        # Dashboard KPIs
        "kpi_threats": "التهديدات التي تم تحييدها",
        "kpi_canaries": "مصائد الطعوم النشطة",
        "kpi_canaries_val": "4 مجلدات مراقبة",
        "kpi_processes": "العمليات الخاضعة للمراقبة",
        "kpi_quarantine": "الملفات المعزولة",
        
        # Shields
        "shields_title": "دروع الحماية الاستباقية النشطة",
        "sh_behavioral_title": "درع مراقبة سلوك البرامج المشبوهة (Behavioral Shield)",
        "sh_behavioral_desc": "يراقب البرامج الشغالة ويكتشف محاولات الاختراق وحقن الذاكرة واستغلال أوامر الويندوز الخفية حتى لو كان الفيروس جديداً تماماً.",
        "sh_ransomware_title": "مصائد برمجيات الفدية الذكية (Ransomware Decoy Traps)",
        "sh_ransomware_desc": "يزرع ملفات تمويه في مجلداتك الحيوية؛ وعندما يحاول فيروس فدية لمسها، يتم رصده وقتل برنامجه فوراً قبل أن يصل لملفاتك الحقيقية.",
        "sh_network_title": "حارس الاتصالات ومحاولات سحب البيانات (Network Sentinel)",
        "sh_network_desc": "يمنع محاولات التجسس وسحب البيانات، ويغلق فوراً أي اتصال خارجي مشبوه يفتحه مخترق أو فيروس.",
        "sh_persistence_title": "حامي بدء التشغيل التلقائي (Startup & Registry Guard)",
        "sh_persistence_desc": "يمنع الفيروسات وأحصنة طروادة من تثبيت نفسها لتعمل في الخفاء كلما قمت بفتح الكمبيوتر.",
        
        # Actions
        "actions_title": "أدوات التدخل السريع وعزل الجهاز",
        "btn_isolate": "🚨 عزل الجهاز فوراً (قطع الإنترنت لمنع انتشار الفيروس)",
        "btn_restore": "🔄 استعادة اتصال الشبكة والإنترنت",
        "btn_refresh_canaries": "🛡️ إعادة تهيئة ملفات الطُعم الذكية",
        
        # Scanner Tab
        "scan_placeholder": "اختر ملفاً لفحصه واكتشاف ما إذا كان يحتوي على تشفير خبيث أو أكواد غير آمنة...",
        "btn_browse": "📁 اختيار ملف",
        "btn_scan": "⚡ بدء الفحص العميق",
        "scan_ready": "جاهز للفحص",
        "btn_quarantine_scan": "🔒 نقل الملف المشبوه إلى قبو العزل فوراً",
        
        # Process Tab
        "proc_title": "البرامج الشغالة حالياً ودرجة خطورتها التقديرية",
        "btn_refresh_proc": "🔄 تحديث قائمة البرامج",
        
        # Logs Tab
        "logs_title": "سجل الأحداث الأمنية والعمليات المنفذة",
        "btn_clear_logs": "🧹 مسح السجل",
        
        # Quarantine Tab
        "quarantine_title": "الملفات المعزولة والمنزوعة الخطورة (مشفرة داخل القبو الآمن)",
        "btn_refresh_vault": "🔄 تحديث القبو",
        
        # Settings Tab
        "settings_title": "إعدادات وتفضيلات برنامج TBD",
        "settings_section_general": "عام وبدء التشغيل",
        "settings_autostart": "تشغيل TBD تلقائياً مع بدء إقلاع الويندوز",
        "settings_autostart_desc": "يحافظ على أمان جهازك وحمايته منذ اللحظة الأولى لفتح الكمبيوتر.",
        "settings_language": "لغة البرنامج (Language)",
        "settings_theme": "المظهر والألوان",
        "theme_dark": "المظهر الداكن (Cybersecurity Dark)",
        "theme_light": "المظهر الفاتح (Light)",
        "theme_system": "حسب إعدادات الويندوز (System)",
        
        "settings_section_defense": "سلوك التعامل مع التهديدات",
        "settings_autokill": "إيقاف البرامج الخبيثة وعزلها تلقائياً وبسرعة فائقة",
        "settings_autokill_desc": "عند تفعيل هذا الخيار، يتم قتل العمليات المشبوهة وتطويق فيروسات الفدية فور رصدها دون انتظار.",
        "settings_sensitivity": "مستوى حساسية الفحص الاستباقي",
        "sens_normal": "عادي (Normal) - متوازن ومناسب للاستخدام اليومي بدون إزعاج",
        "sens_high": "مرتفع (High) - تدقيق مشدد على البرامج والسكريبتات غير الموثوقة",
        "sens_strict": "صارم (Strict) - حماية قصوى وتدقيق فائق (مناسب عند الشك في وجود هجوم)",
        
        "settings_section_canary": "أماكن نشر مصائد فيروسات الفدية (Decoys)",
        "canary_desktop": "حماية مجلد سطح المكتب (Desktop)",
        "canary_documents": "حماية مجلد المستندات (Documents)",
        "canary_downloads": "حماية مجلد التنزيلات (Downloads)",
        "canary_pictures": "حماية مجلد الصور (Pictures)",
        
        "btn_save_settings": "💾 حفظ الإعدادات",
        "btn_reset_settings": "↺ استعادة الإعدادات الافتراضية",
        "settings_saved_msg": "تم حفظ الإعدادات بنجاح وتحديث النظام.",
        "settings_reset_msg": "تمت استعادة الإعدادات الأصلية الافتراضية.",
        
        # Dialogs
        "confirm_isolation_title": "تأكيد عزل الجهاز",
        "confirm_isolation_msg": "هل أنت متأكد من رغبتك في عزل الجهاز عن الشبكة بالكامل؟\n\nسيتم تعطيل كروت الشبكة والإنترنت لحصار أي هجوم ومنع تسريب بياناتك.",
        "isolation_success": "تم فصل كروت الشبكة بنجاح وعزل الجهاز عن أي خطر خارجي.",
        "restore_success": "تمت إعادة تشغيل الشبكة والإنترنت بنجاح.",

        # Demo Suite Strings
        "demo_title": "🚨 منصة اختبار TBD الحية (عرض أمام لجان التحكيم ISEF)",
        "demo_subtitle": "منصة اختبار حية للمشروع أمام لجان التحكيم • محاكاة آمنة ومتحكم بها 100%",
        "demo_status_ready": "الحالة: جاهز للعرض أمام لجان التحكيم. تأكد أن برنامج TBD مفتوح بجانب هذه النافذة.",
        "demo_btn_cleanup": "🧹 تنظيف مخلفات الاختبار",
        "demo_badge_prefix": "اختبار #",

        "demo1_title": "محاكاة هجوم فيروس فدية مشفر (Ransomware Encryption Attack)",
        "demo1_desc": "يقوم هذا الزر بمحاكاة فيروس فدية يحاول تشفير ملفات المستخدم على سطح المكتب بإنتروبيا عالية (7.8/8.0). انظر لشاشة TBD فوراً لتشاهد كيف يرصد محاولة التشفير ويقتل العملية في أقل من نصف ثانية!",
        "demo1_btn": "💥 إطلاق هجوم الفدية التجريبي",
        "demo1_running": "جاري محاكاة هجوم الفدية... راقب شاشة TBD الآن!",
        "demo1_dialog_title": "تم إطلاق المحاكاة",
        "demo1_dialog_msg": "تمت محاكاة محاولة تشفير ملف الطعم بنجاح!\nالمسار: {}\n\nانظر إلى شاشة TBD: ستشاهد تنبيهاً باللون الأحمر يوضح رصد التشفير اللحظي وتوقف الهجوم!",
        "demo1_done": "نجحت محاكاة الفدية! تأكد من ظهور التنبيه الأحمر في TBD.",

        "demo2_title": "محاكاة استغلال أوامر الويندوز الخفية (LOLBin Obfuscation)",
        "demo2_desc": "يقوم بتشغيل سكريبت مموّه ومخفي بتقنية Base64، ومحاولة استدعاء أوامر حذف النسخ الاحتياطية. ستشاهد TBD يكتشف العملية ويصنفها بدرجة خطورة عالية ويوقفها فوراً.",
        "demo2_btn": "⚡ إطلاق سكريبت الاختراق الخفي",
        "demo2_running": "جاري إطلاق سكريبت الـ LOLBin المخفي...",
        "demo2_dialog_title": "تم تشغيل السكريبت",
        "demo2_dialog_msg": "تم إطلاق أمر PowerShell مخفي ومموّه بنظام Base64!\n\nانظر إلى تبويب (سجل الأحداث) أو (البرامج النشطة) في TBD لرؤية كيف يكتشف التمويه السلوكي ويعطيه درجة خطورة عالية!",
        "demo2_done": "تم إطلاق سكريبت الـ LOLBin. افحص سجل TBD.",

        "demo3_title": "محاكاة فتح اتصال خلفي مع مخترق (C2 / Reverse Shell)",
        "demo3_desc": "يحاول فتح اتصال خارجي مشبوه عبر المنفذ 4444 الشهير ببرمجيات التجسس. ستلاحظ TBD يرصد المنفذ المشبوه ويغلق الاتصال فوراً لحماية خصوصية الجهاز.",
        "demo3_btn": "🌐 إطلاق اتصال تجسس خارجي",
        "demo3_running": "جاري محاولة فتح اتصال خارجي مشبوه على المنفذ 4444...",
        "demo3_dialog_title": "تمت المحاولة",
        "demo3_dialog_msg": "تمت محاولة فتح اتصال خارجي على المنفذ 4444 (المعروف بـ Metasploit Reverse Shell).\n\nمراقب الشبكة في TBD يقوم بفحص وتطويق أي اتصال خارجي غير مصرح به.",
        "demo3_done": "تم فحص اتصال المنفذ 4444 في TBD.",

        "demo4_title": "محاكاة تثبيت فيروس في بدء التشغيل (Startup Persistence)",
        "demo4_desc": "يحاول حقن مفتاح جديد داخل سجل الويندوز (Run Key) ليعمل تلقائياً مع فتح الجهاز. يرصد TBD التغيير في الـ Registry ويطلقه كتنبيه أمني فوري في السجلات.",
        "demo4_btn": "📌 حقن مفتاح تثبيت تلقائي في السجل",
        "demo4_running": "جاري محاولة إضافة مفتاح إقلاع في الـ Registry...",
        "demo4_dialog_title": "تم حقن المفتاح في السجل",
        "demo4_dialog_msg": "تمت إضافة مفتاح تشغيل تلقائي تجريبي باسم 'TBD_Judge_Demo_Persistence'.\n\nحامي بدء التشغيل في TBD سيكتشف التغيير ويطلقه في سجل الأحداث (Logs) كإنذار اختراق للـ Registry!",
        "demo4_done": "تم حقن المفتاح بنجاح! راقب سجل أحداث TBD.",

        "demo5_title": "إنشاء عينة خبيثة وهمية لفحصها بالفاحص الذكي (Heuristic Scanner)",
        "demo5_desc": "ينشئ ملفاً وهمياً على سطح المكتب يحمل خصائص تشفير ومحتوى مشبوه، لتطلب من الحكام فحصه في تبويب (فحص الملفات) داخل TBD ورؤية تحليل الأقسام والإنتروبيا وزر العزل.",
        "demo5_btn": "📁 إنشاء العينة التجريبية على سطح المكتب",
        "demo5_running": "جاري إنشاء العينة الخبيثة الوهمية...",
        "demo5_dialog_title": "تم إنشاء العينة بنجاح",
        "demo5_dialog_msg": "تم إنشاء ملف العينة على سطح المكتب باسم:\n{}\n\nالخطوة التالية أمام الحكام:\n1. افتح تبويب 'فحص الملفات' (File Scanner) في TBD.\n2. اختر هذا الملف واضغط 'بدء الفحص العميق'.\n3. سيعرض البرنامج للحكام إنتروبيا الملف العالية (7.8/8.0) وتصنيفه كتهديد خبيث 100/100 مع إمكانية نقله لقبو العزل!",
        "demo5_done": "تم إنشاء العينة: {} على سطح المكتب.",

        "demo_cleanup_title": "تم التنظيف",
        "demo_cleanup_msg": "تم تنظيف: {}",
        "demo_cleanup_none": "لا توجد مخلفات مؤقتة",
        "demo_cleanup_regkey": "مفتاح السجل التجريبي",
        "demo_cleanup_sample": "ملف العينة من سطح المكتب",

        "demo_error": "خطأ",
        "demo_error_msg": "تعذر تنفيذ المحاكاة: {}"
    }
}

class I18n:
    """Localization helper class."""
    _current_lang = "en"

    @classmethod
    def set_language(cls, lang: str):
        if lang in STRINGS:
            cls._current_lang = lang

    @classmethod
    def get_language(cls) -> str:
        return cls._current_lang

    @classmethod
    def is_rtl(cls) -> bool:
        """Returns True if current language is right-to-left."""
        return cls._current_lang == "ar"

    @classmethod
    def t(cls, key: str, default: str = "") -> str:
        """Translates a key according to the current language."""
        lang_dict = STRINGS.get(cls._current_lang, STRINGS["en"])
        if key in lang_dict:
            return lang_dict[key]
        # Fallback to English
        return STRINGS["en"].get(key, default or key)
