package com.buptnsrc.krrecover.modelDetect.Util;

import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;

import com.alibaba.fastjson.JSONObject;

import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.dexbacked.reference.DexBackedStringReference;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import org.jf.dexlib2.iface.DexFile;

import com.cybozu.labs.langdetect.*;


public class extractFeature {
    /**
     * 特征集：
     *  md5,        activities,     services,   cmdList,    APIsList,   nameList,   keywordsListIn,     keywordsListEqual,
     *  pkgList,    permList,       urlList,    phoneList,  emailList,  filesize,   potential_misBhve,  SdkVersion,
     *  Day,Month,Year,             hasVideo,   n_activities,           n_intents,  n_providers,        n_services,
     *  receiver_priority,          intents_in_code,        hasHTMLDocuments                hasFakeInstaller3or4Files,
     *  hasIncognitoAPK,            hasIncognitoDEX,        hasMultiDEX,            package_name_len,   package_name_shannon,
     is_mismatch_components_and_package,     app_name_language,      so_files,   elf_feature,        potential_misBhve_cnt
     * **/

    // String 类型
    String md5="";
    String Year="";
    String Month="";
    String Day="";
    String receiver_priority ="{}";
    String app_name_language="";


    ArrayList activities=new ArrayList();
    ArrayList services=new ArrayList();
    ArrayList permList=new ArrayList();
    ArrayList<String> intents_in_code=new ArrayList();
    ArrayList nameList=new ArrayList();
    ArrayList<String> pkgList =new ArrayList<>();//获取 APK 中存在的包名(如第三方包，等）
    ArrayList<String> potential_misBhve=new ArrayList();
    ArrayList<String> urlList = new ArrayList();
    ArrayList<String> phoneList=new ArrayList();
    ArrayList<String> emailList=new ArrayList();
    ArrayList<String> so_files=new ArrayList<>();


    Map<String,Integer> cmdList=new HashMap<>();
    Map<String,Integer> APIsList=new HashMap<>();
    Map<String,Integer> keywordsListIn=new HashMap<>();
    Map<String,Integer> keywordsListEqual=new HashMap<>();
    Map<String,Integer> elf_feature=new HashMap<>();



    float package_name_shannon=0;
    float fileSize=0; //（还未确认单位是否与python版一致）


    int SdkVersion=0;
    int n_activities=0;
    int n_services=0;
    int n_intents=0;
    int n_providers=0;
    int package_name_len=0;
    int potential_misBhve_cnt=0;


    Boolean hasVideo=false;
    Boolean hasHTMLDocuments=false;
    Boolean hasFakeInstaller3or4Files=false;
    Boolean hasIncognitoDEX=false;
    Boolean hasIncognitoAPK=false;
    boolean is_mismatch_components_and_package=false;



    PackageManager packageManager=null;
    String apkSourceURI="";
    List<DexBackedStringReference> z_Strings=new ArrayList<>();
    File f=null;
    String appName="";
    DexFile dexFile=null;
    ArrayList<String> methods=null;
    Context context=null;
    String pkgName="";
    ProviderInfo[] providers=null;
    boolean hasMultiDEX=false;

    //        elf_feature;

    String [] suspicious_cmds = new String[]{"su", "chmod", "insmod", "mount", "sh", "chown", "killall", "kill -9", "pm install -r",
            "chmod -R 777", "reboot", "hosts", "getprop", "mkdir", "ln", "ps", "killProcess", "adb shell",
            "mount -o remount,rw", "am", "pm", "cat", "ls", "ls -l", "mkdir", "pm uninstall -k", "rm ",
            "rm -r ", "restorecon", "restorecon -R "};
    String [] suspicious_APIs = new String[]{"getDeviceID", "getInstalledApplications", "getOutputStream", "getInputStream",
            "HttpURLConnection", "openConnection", "sendTextMessage",  "getLastKnownLocation",
            "getFromLocation", "installPackage", "startActivityForResult", "setComponent", "URL",
            "openFileOutput", "getAssets", "lockNow", "exec", "getDefaultSmsPackage","setComponentEnabledSetting",
            "abortBroadcast", "divideMessage","sendMultipartTextMessage", "sortTextFlavorsByType"};
    String [] suspicious_names = new String[]{"刷钻", "刷赞", "刷人气", "外挂", "免流", "修改器", "神器", "福利", "锁屏", "破解器", "秒赞", "卡钻", "QQ会员",
            "诱惑", "美女", "快播", "影院", "小视频", "成人", "看片", "情色", "宅男", "福利", "午夜", "岛国", "脱衣服",
            "写真", "狼友", "裸露", "调教", "丝袜", "火辣", "情趣", "裸聊", "凌辱", "porn", "xxoo", "sex", "av", "波霸",
            "qvod", "播播", "啪啪啪", "激情", "爽片", "撸撸", "情涩", "情欲", "色戒", "色色", "色影", "涩欲", "涩爱",
            "涩涩", "私房", "私蜜", "桃色", "无码", "淫欲", "欲爱", "欲望", "欲女", "欲涩"};
    String [] suspicious_keywords_In = new String[]{"到期时间", "设置成功", "开始群发", "拦截消息", "随机码", "密码", "发送失败", "对发",
            "正确格式 手机号码#内容",  "锁", "收费", "序列", "解除", "识别码", "元", "费", "支付", "收取", "免费",
            "短信", "上传", "监视",".TOR_SERVICE",".torproject.","/torproject/",".onion"};
    String [] suspicious_keywords_Equal = new String[]{"lock", "Llengmo.lockphone.lock", "content:sms", "pdus", "Telephony.SMS-RECEIVED",
            "mailto", "NEW_OUTGOING_CALL", "android.intent.action.RUN",  "Browser.BOOKMARKS_URI",
            "MailFrom_Passa", "MailFrom_name", "Lcom/elev/MyService", "Lcom/elev/XRece", "Contract",
            "nmyxp", "nmhup", "nmop", "nmpp", "nmmp", "gcc", "pnumber", "tel:", "tel:%23%2321%23",
            "tel:**21*", "mygirl", "diao", "islj", "jjyy", "SOME", "9999#", "zdkey",
            "android.package-archive",  "LogCatBroadcaster", "ADRTLogCatReader", "AES",
            "content://sms", "FLAG_ACTIVITY_NEW_TASK", "aide", "content://sms/inbox",
            "content://sms/sent", "content://sms/draft", "device_policy",
            "content://sms/conversations/", "pay", "Payment", "￥", "alpay", "$", "moneXy", "MoneyPak",
            "Qiwi +", "Педофилия", "Видеоматериалов", "запрещенных", "Ваш телефон", "заблокирован",
            "МВД РФ за", "разблокировки", "Аппарата", "Оплатить", "номер", "В течении 24 часов",
            "разблокируем", "PornDroid", "锁",
            "content://browser/bookmarks", "content://telephony/carriers/preferapn","vnd.android-dir/mms-sms",
            "smsto"};
    String [] suspicious_pkg_names = new String[]{"Lcom.lock", "Lcom.skymobi", "Lcom.cmnpay", "Lcom.iappay", "Lcom.wimipay",
            "Lcom.appquanta", "Lcom.jpush", "Lcom.waps", "Lcom.baidu.mobads", "Lcom.youmi",
            "Lcom.google.ads", "Lcom.admob", "Lcom.startapp", "Lcom.adwo", "Lcom.domob", "Lcom.adsmogo",
            "Lcom.facebook.ads", "Lcom.inmobi", "Lcom.adchina", "Lcom.adfonic", "Lcom.adwhirl",
            "Lcom.guohead", "Lcom.madhouse", "Lcom.fractalist", "Lcom.qq.e", "Lcom.e4a", "Lcom.airpush",
            "Lcom.h", "aide", "ADRTLogCatReader", "LogCatBroadcaster", "lock", "Llengmo.lockphone","Lcom.geinimi",
            "Lnet.youmi"};
    String[] mali_API=new String[]{"Landroid/content/Context;","getSystemService","Landroid/content/ContextWrapper;","Landroid/view/ContextThemeWrapper;",
        "Landroid/support/v7/view/ContextThemeWrapper;","Landroid/telephony/TelephonyManager;","getDeviceId",
        "Landroid/content/pm/PackageManager;","getLaunchIntentForPackage","Lcom/android/append/LauncherActivity;","startActivity",
        "Ljava/net/HttpURLConnection;","getInputStream","Landroid/content/ContentResolver;","update","Landroid/content/ContentProvider;",
        "Landroid/content/ContentValues;","put","Lcn/cmgame/billing/api/GameInterface;","initializeApp","Lcn/cmgame/billing/api/GameInterface;","doBilling",
        "Landroid/location/LocationManager;","getLastKnownLocation","Ljava/net/Socket;","Socket","Ljava/net/Socket;","getOutputStream",
        "Landroid/net/LocalSocket;","getOutputStream","Ljava/net/ServerSocket;","ServerSocket","Ljava/net/ServerSocket;","getInputStream",
        "Landroid/net/LocalSocket;","getInputStream","Landroid/content/Intent;","addCategory","Landroid/content/Intent;","createChooser","Ljava/io/FileInputStream;",
            "Ljava/io/FileOutputStream;","Ljava/io/InputStream;","Ljava/io/OutputStream;","Ljava/io/File;","delete","Landroid/view/View;","setVisibility",
        "Ldalvik/system/DexClassLoader;","Ldalvik/system/DexClassLoader;","loadClass","Ljava/lang/Runtime;","getRuntime", "Ljava/lang/Runtime;","exec",
        "Landroid/view/WindowManager;","addView","Landroid/view/WindowManager/LayoutParams;", "Landroid/view/WindowManager/LayoutParams;","FLAG_FULLSCREEN",
        "Landroid/view/WindowManager$LayoutParams;", "Landroid/telephony/TelephonyManager;","getNetworkOperator", "Landroid/telephony/TelephonyManager;",
            "getSimOperator","Landroid/telephony/TelephonyManager;","getSubscriberId","Landroid/net/Proxy;","getDefaultHost","getDefaultPort",
    "android.telephony.SmsManager;","sendTextMessage", "sendMultipartTextMessage",    "sendTextMessageWithoutPersisting",    "android.telephony.gsm.SmsManager;",
    "sendMultipartTextMessage","Landroid/content/pm/PackageManager;","getInstalledPackages",    "Ljava/lang/Class;","forName",
            "Ljava/lang/Object;","getClass","Ljava/lang/reflect/Method;","invoke",
    "Landroid/provider/Settings$Secure;","getString","Landroid/content/pm/PackageManager;","setComponentEnabledSetting","Landroid/telephony/gsm/SmsMessage;","getoriginatingAddress",
    "Landroid/telephony/SmsMessage;","getoriginatingAddress","Landroid/telephony/SmsMessage;","getDisplayoriginatingAddress",
    "Landroid/app/ActivityManager;","getProcessMemoryInfo", "Landroid/app/AlarmManager;","setRepeating", "Landroid/app/PendingIntent;","getBroadcast",
    "Landroid/app/AlarmManager;","cancel",    "Landroid/content/ContentResolver;","delete",    "Landroid/provider/Telephony$Sms;","getDefaultSmsPackage",
    "Landroid/media/AudioManager;","setRingerMode",    "Landroid/os/Build$VERSION",    "android.telephony.gsm.SmsMessage;","getMessageBody",
    "Landroid/telephony/SmsMessage;","getMessageBody",    "Landroid/telephony/SmsMessage;","getDisplayMessageBody",    "Landroid/os/Process;","killProcess",
    "Landroid/app/ActivityManager;","killBackgroundProcesses",    "Ljavax/crypto/Cipher;","getInstance",    "Ljavax/crypto/spec/SecretKeySpec;",
    "Ljavax/crypto/Cipher;",    "Ljavax/crypto/Cipher;","doFinal",    "Landroid/telephony/TelephonyManager;","getLine1Number",    "Ljava/lang/Thread;",
    "start",    "Ljava/lang/Class;","getResourceAsStream",    "Lorg/apache/http/impl/client/DefaultHttpClient;","execute",
    "Lorg/apache/http/HttpResponse;","getEntity",    "Landroid/os/Environment;","getDataDirectory",    "Landroid/os/Environment;","getDownloadCacheDirectory",
    "Landroid/os/Environment;","getExternalStorageDirectory",    "Landroid/os/Environment;","getExternalStorageState",    "Landroid/app/ActivityManager;",
            "getRunningAppProcesses",    "Landroid/app/ActivityManager;","getRunningTasks",    "Landroid/database/sqlite/SQLiteDatabase;","execSQL",
    "Landroid/content/res/Resources;","openRawResource",    "Ljava/io/InputStreamReader",    "Landroid/app/admin/DeviceAdminReceiver;","onDisableRequested",
    "Landroid/app/admin/DevicePolicyManager", "resetPassword",    "Landroid/app/admin/DevicePolicyManager", "lockNow",     "Landroid/app/admin/DevicePolicyManager",
    "Ljava/net/HttpURLConnection;","connect",    "Ljava/net/HttpURLConnection;","getOutputStream",    "Landroid/webkit/WebViewClient;"
    };
    Map<String,Boolean> map_mali_API=new HashMap<>();


    boolean actionCC =  false;
    boolean device_admin_permission=false;
    boolean http_pay=false;
    boolean https_pay=false;
    boolean setDataEnabled=false;
    boolean setMobileDataEnabled=false;
    boolean searchmobileonline=false;
    boolean BOOKMARKS=false;
    boolean SHORTCUTS=false;
    boolean COMMANDS_STATUS=false;
    boolean ACTIVATION=false;
    boolean TERMINATE=false;
    boolean UNEXPECTED_EXCEPTION=false;
    boolean INFO=false;




    public extractFeature(String apkSourceUri, String pkgName,String appName,Context context){
        this.apkSourceURI=apkSourceUri;
        f= new File(apkSourceURI);
        this.packageManager= context.getPackageManager();
        this.pkgName=pkgName;
        z_Strings=getStrings();
        filterZString();
        this.appName=appName;
        dexFile=ApkUtil.getDexFile(apkSourceUri);
        this.context=context;
        this.methods= ApkUtil.getMethods(dexFile); // 提取dex文件中的所有method名称
        md5=getMD5();
        getActivities();
        getServices();
        get_suscipious_names();
        get_suspicious_package_names();//获取 APK 中存在的包名(如第三方包，等）
        getPermissions();
        fileSize=getFileSize(); //（还未确认单位是否与python版一致）
        n_activities=activities.size();
        n_services=services.size();
        n_intents=n_activities+n_services;
        n_providers=getProviderNum();
        hasVideoOrHTML();// 用于获取 hasVideo hasHTMLDocuments  hasFakeInstaller3or4Files 的值
        /***在总特征集里，记得加上这3个,他们的值由hasVideoOrHTML()计算而来。
        Boolean hasVideo;
        Boolean hasHTMLDocuments;
        Boolean hasFakeInstaller3or4Files;
         ArrayList<String> so_files
         */
        hasMultiDEX=hasMultiDEX();
        package_name_len=pkgName.length();
        package_name_shannon= (float) entropy();
        is_mismatch_components_and_package=is_mismatch_components_and_package();
        app_name_language=detect_app_name_language();
        potential_misBhve=get_malicious_activities();
        Map<String,String> t=get_time();
        Year=t.get("year");
        Month=t.get("month");
        Day=t.get("day");
        potential_misBhve_cnt=potential_misBhve.size();
//        xmlHandle();
//        xmlPr();
//        cmdList=get_suspicious_cmds();
//        APIsList=get_suspicious_APIs();
//        keywordsListIn=get_suspicious_keywords_in();
//        keywordsListEqual=get_suspicious_keywords_equal();
//        urlList = get_suspicious_urls();
//        phoneList=get_suspicious_phones();
//        emailList=get_suspicious_emails();
//        intents_in_code=get_intents_in_code();

//        elf_feature;
        //hasIncognitoDEX 设置成全局变量，继续整合到hasVideoOrHTML里，
//        Boolean hasIncognitoAPK=true;/*** 这个是用于判断apk里是否包含子apk且子apk进行了匿名（即不以.apk为后缀，而是故意以其他的为后缀）*/
        // SdkVersion 目前获取不到，改天试试

    }

    public void filterZString(){
        /***    遍历z_String，提取可疑信息*/
        String s="";
        Iterator<DexBackedStringReference> iterator =z_Strings.iterator();
        while (iterator.hasNext()) {
            DexBackedStringReference current = iterator.next();
            s=current.getString();

            if(s.contains("android.provider.Telephony.ACTION_CHANGE_DEFAULT")){
                actionCC=true;
            }else if(s.contains("android.app.action.ADD_DEVICE_ADMIN")){
                device_admin_permission=true;
            }else if(s.contains("http){//pay")){
                http_pay=true;
            }else if(s.contains("https){//pay")){
                https_pay=true;
            }else if(s.contains("setDataEnabled" )){
                setDataEnabled=true;
            } else if(s.contains("setMobileDataEnabled")){
                setMobileDataEnabled=true;
            }else if(s.contains("http){//www.searchmobileonline.com/")){
                searchmobileonline=true;
            }else if(s.contains("BOOKMARKS")){
                BOOKMARKS=true;
            }else if(s.contains("SHORTCUTS")){
                SHORTCUTS=true;
            }else if(s.contains("COMMANDS_STATUS")){
                COMMANDS_STATUS=true;
            }else if(s.contains("ACTIVATION" )){
                ACTIVATION=true;
            } else if(s.contains("TERMINATE")){
                TERMINATE=true;
            }else if(s.contains("UNEXPECTED_EXCEPTION")){
                UNEXPECTED_EXCEPTION=true;
            }else if(s.contains("INFO")){
                INFO=true;
            }else if(s.contains("android.provider") || s.contains("android.intent")) {
                intents_in_code.add(s);
            }else if(detect_email(s)){
                emailList.add(s);
            }else if(detect_phone(s)){
                phoneList.add(s);
            }else if(detect_url(s)){
                urlList.add(s);
            }

            for(String keyword:mali_API){
                if(s.equals(keyword)){
                    if(!map_mali_API.containsKey(s)){
                        map_mali_API.put(s,true);
                    }
                }
            }


            String k_tmp=null;
            int c=1;
            for(String keyword:suspicious_keywords_Equal){
                if(s.equals(keyword)){
                    k_tmp=keyword+"_keyword";
                    if(keywordsListEqual.containsKey(k_tmp)){
                        c=keywordsListEqual.get(k_tmp)+1;
                        keywordsListEqual.put(k_tmp,c);
                    }else {
                        keywordsListEqual.put(k_tmp,1);
                    }
                }
            }

            c=1;
            for(String keyword:suspicious_keywords_In){
                if(s.contains(keyword)){
                    k_tmp=keyword+"_keyword";
                    if(keywordsListIn.containsKey(k_tmp)){
                        c=keywordsListIn.get(k_tmp)+1;
                        keywordsListIn.put(k_tmp,c);
                    }else {
                        keywordsListIn.put(k_tmp,1);
                    }
                }
            }

            c=1;
            for(String keyword:suspicious_APIs){
                if(s.contains(keyword)){
                    k_tmp=keyword+"_api";
                    if(APIsList.containsKey(k_tmp)){
                        c=APIsList.get(k_tmp)+1;
                        APIsList.put(k_tmp,c);
                    }else {
                        APIsList.put(k_tmp,1);
                    }
                }
            }

            c=1;
            for(String keyword:suspicious_cmds){
                if(s.equals(keyword)){
                    k_tmp=keyword+"_cmd";
                    if(cmdList.containsKey(k_tmp)){
                        c=cmdList.get(k_tmp)+1;
                        cmdList.put(k_tmp,c);
                    }else {
                        cmdList.put(k_tmp,1);
                    }
                }
            }


        }
    }

    public ArrayList<String> get_malicious_activities(){
        /** 根据不同的 API 组合规则, 获取不同的特征。用于提取恶意行为，这里面写了很多敏感的操作，将做一一说明*/
        ArrayList<String> potential_misBhve=new ArrayList<>();

        /***   预处理，用于判断是否"使用了指定的class" */
        String onlyMethodName=null;
        String onlyClassName=null;
        boolean IvParameterSpec=false;
        boolean getWindow1 = false;
        boolean  cipherOutputStream = false;
        boolean getLogcat = false;
        boolean getADRT=false;
        // 重写"在设备管理器权限被取消前所调用的方法"
        boolean onDisabled = false;
        boolean getResources =false;
        boolean getSystemService =false;
        boolean geinimi_package =false;
        boolean abortBroadcast=false;
        boolean deny_button1=false;
        boolean deny_button2=false;
        boolean deny_button3=false;
        boolean deny_button4=false;
        for(String m:methods){
            onlyClassName=m.split(";->")[0];
            IvParameterSpec = onlyClassName.contains("Ljavax/crypto/spec/IvParameterSpec");
            getWindow1 = onlyClassName.contains("Landroid/view/WindowManager$LayoutParams");
            cipherOutputStream=onlyClassName.contains("Ljavax/crypto/CipherOutputStream");
            getLogcat = onlyClassName.contains("LLogCatBroadcaster");
            getADRT = onlyClassName.contains("Ladrt/R/ADRTLogCatReader");
            onDisabled = onlyClassName.contains("Landroid/app/admin/DeviceAdminReceiver");
            geinimi_package = onlyClassName.contains("Lcom/geinimi");


            onlyMethodName=m.split(";->")[1];
            getResources = onlyMethodName.contains("getResources");
            getSystemService = onlyMethodName.contains("getSystemService");
            abortBroadcast = onlyMethodName.contains("abortBroadcast");
            deny_button1 = onlyMethodName.contains("dispatchKeyEvent");
            deny_button2 = onlyMethodName.contains("onKeyUp");
            deny_button3 = onlyMethodName.contains("onKeyDown");
            deny_button4 = onlyMethodName.contains("onBackPressed");
        }
        /***   预处理，用于判断是否"使用了指定的permission" */
        boolean writeSD =false;
        boolean mount=false;
        boolean alertWindow=false;
        boolean boot=false;
        boolean wakeLock=false;
        boolean getTasks=false;
        boolean changeWifi=false;
        String p="";
        for(Object per:permList){
            p=per.toString();
            if(p.equals("android.permission.WRITE_EXTERNAL_STORAGE")){
                writeSD=true;
            }
            if(p.equals("android.permission.MOUNT_UNMOUNT_FILESYSTEMS")){
                mount=true;
            }
            if(p.equals("android.permission.SYSTEM_ALERT_WINDOW")){
                alertWindow=true;
            }
            if(p.equals("android.permission.RECEIVE_BOOT_COMPLETED")){
                boot=true;
            }
            if(p.equals("android.permission.WAKE_LOCK")){
                wakeLock=true;
            }
            if(p.equals("android.permission.GET_TASKS")){
                getTasks=true;
            }
            if(p.equals("android.permission.CHANGE_WIFI_STATE")){
                changeWifi=true;
            }

            if(writeSD && mount && alertWindow && boot && wakeLock &&getTasks){
                break;
            }
        }

        /** 开始 ***/

        // 表示执行锁机并重置密码操作
//        getreset = list(self.dx.find_methods("Landroid/app/admin/DevicePolicyManager", "resetPassword", "."))
//        getLock = list(self.dx.find_methods("Landroid/app/admin/DevicePolicyManager", "lockNow", "."))
//        getSth = list(self.dx.find_methods("Landroid/app/admin/DevicePolicyManager", "", "."))
        boolean  getreset =  map_mali_API.containsKey("Landroid/app/admin/DevicePolicyManager;") && map_mali_API.containsKey("resetPassword");
        boolean  getLock = map_mali_API.containsKey("Landroid/app/admin/DevicePolicyManager;") && map_mali_API.containsKey("lockNow");
        boolean  getSth = map_mali_API.containsKey("Landroid/app/admin/DevicePolicyManager;") ;
        if (getreset && getLock){
            potential_misBhve.add("LockNow and ResetPassword");
        }


        /*** 表示读取了手机的 IMEI 码*/
//        boolean  Context_getSystemService = methods.contains(String.valueOf("Landroid/content/Context;->getSystemService"));
//        boolean  ContextWrapper_getSystemService = methods.contains("Landroid/content/ContextWrapper;->getSystemService");
//        boolean  view_ContextThemeWrapper_getSystemService = methods.contains("Landroid/view/ContextThemeWrapper;->getSystemService");
//        boolean  v7_ContextThemeWrapper_getSystemService = methods.contains("Landroid/support/v7/view/ContextThemeWrapper;->getSystemService");
//        boolean  TelephonyManager_getDeviceId = methods.contains("Landroid/telephony/TelephonyManager;->getDeviceId");
        boolean  Context_getSystemService =  map_mali_API.containsKey("Landroid/content/Context;") && map_mali_API.containsKey("getSystemService");
        boolean  ContextWrapper_getSystemService = map_mali_API.containsKey("Landroid/content/ContextWrapper;") && map_mali_API.containsKey("getSystemService");
        boolean  view_ContextThemeWrapper_getSystemService = map_mali_API.containsKey("Landroid/view/ContextThemeWrapper;") && map_mali_API.containsKey("getSystemService");
        boolean  v7_ContextThemeWrapper_getSystemService = map_mali_API.containsKey("Landroid/support/v7/view/ContextThemeWrapper;") && map_mali_API.containsKey("getSystemService");
        boolean  TelephonyManager_getDeviceId = map_mali_API.containsKey("Landroid/telephony/TelephonyManager;") && map_mali_API.containsKey("getDeviceId");
        if( (Context_getSystemService || ContextWrapper_getSystemService || view_ContextThemeWrapper_getSystemService || v7_ContextThemeWrapper_getSystemService) && TelephonyManager_getDeviceId) {
            potential_misBhve.add("Read IMEI");  // 判断是否进行了IMEI的读取
        }

        /** 特征 Does Cipher, 表示 执行了 加密操作, 下列 API 为执行加密操作使用的 加密函数 **/
//        boolean Cipher_getInstance=methods.contains("Ljavax/crypto/Cipher;->getInstance");
//        boolean SecretKeySpec_init = methods.contains("Ljavax/crypto/spec/SecretKeySpec;-><init>");
//        boolean Cipher_init = methods.contains("Ljavax/crypto/Cipher;-><init>");
//        boolean Cipher_doFinal =methods.contains("Ljavax/crypto/Cipher;->doFinal");

        boolean Cipher_getInstance=map_mali_API.containsKey("Ljavax/crypto/Cipher;") && map_mali_API.containsKey("getInstance");
        boolean SecretKeySpec_init = map_mali_API.containsKey("Ljavax/crypto/spec/SecretKeySpec;");
        boolean Cipher_init = map_mali_API.containsKey("Ljavax/crypto/Cipher;");
        boolean Cipher_doFinal =map_mali_API.containsKey("Ljavax/crypto/Cipher;") && map_mali_API.containsKey("doFinal");
        if (((Cipher_getInstance && SecretKeySpec_init && Cipher_init) && Cipher_doFinal) || IvParameterSpec){
            potential_misBhve.add("Does Cipher");   //判断是否使用加密函数
        }

        // 表示是否访问 SDcard
//        boolean Environment_getDataDirectory = methods.contains(String.valueOf("Landroid/os/Environment;->getDataDirectory"));
//        boolean Environment_getDownloadCacheDirectory = methods.contains(String.valueOf("Landroid/os/Environment;->getDownloadCacheDirectory"));
//        boolean Environment_getExternalStorageDirectory = methods.contains(String.valueOf("Landroid/os/Environment;->getExternalStorageDirectory"));
//        boolean Environment_getExternalStorageState = methods.contains(String.valueOf("Landroid/os/Environment;->getExternalStorageState"));

                boolean Environment_getDataDirectory = map_mali_API.containsKey("Landroid/os/Environment;") && map_mali_API.containsKey("getDataDirectory");
        boolean Environment_getDownloadCacheDirectory = map_mali_API.containsKey("Landroid/os/Environment;") && map_mali_API.containsKey("getDownloadCacheDirectory");
        boolean Environment_getExternalStorageDirectory = map_mali_API.containsKey("Landroid/os/Environment;") && map_mali_API.containsKey("getExternalStorageDirectory");
        boolean Environment_getExternalStorageState = map_mali_API.containsKey("Landroid/os/Environment;") && map_mali_API.containsKey("getExternalStorageState");
        if (Environment_getDataDirectory || Environment_getDownloadCacheDirectory ||
        Environment_getExternalStorageDirectory || Environment_getExternalStorageState ){
            potential_misBhve.add("Access SDcard");
        }


        // 表示获取地理位置
//        boolean location = methods.contains("Landroid/location/LocationManager;->getLastKnownLocation");
        boolean location = map_mali_API.containsKey("Landroid/location/LocationManager;") && map_mali_API.containsKey("getLastKnownLocation");
        if ((Context_getSystemService || ContextWrapper_getSystemService || view_ContextThemeWrapper_getSystemService
                || v7_ContextThemeWrapper_getSystemService) && location) {
            potential_misBhve.add("Get Location");
        }

//        // 表示执行锁机并重置密码操作
//        boolean getreset = methods.contains("Landroid/app/admin/DevicePolicyManager;->resetPassword");
//        boolean getLock = methods.contains("Landroid/app/admin/DevicePolicyManager;->lockNow");
//        boolean getSth = methods.contains("Landroid/app/admin/DevicePolicyManager;->");
//        if (getreset && getLock) {
//            potential_misBhve.add("LockNow and ResetPassword");
//        }

        // 全屏类锁机特征
//        boolean getWindow = methods.contains("Landroid/view/WindowManager/LayoutParams;->");
//        boolean getFlag = methods.contains("Landroid/view/WindowManager/LayoutParams;->FLAG_FULLSCREEN");
//        boolean getFlag1 = methods.contains("Landroid/view/WindowManager$LayoutParams;->FLAG_FULLSCREEN");
                boolean getWindow = map_mali_API.containsKey("Landroid/view/WindowManager/LayoutParams;");
        boolean getFlag = map_mali_API.containsKey("Landroid/view/WindowManager/LayoutParams;") && map_mali_API.containsKey("FLAG_FULLSCREEN");
        boolean getFlag1 = map_mali_API.containsKey("Landroid/view/WindowManager$LayoutParams;") && map_mali_API.containsKey("FLAG_FULLSCREEN");
        if ((getFlag && getWindow) || (getFlag1 && getWindow1)) {
            potential_misBhve.add("FLAG_FULLSCREEN");
        }

        // 持续弹窗类锁机特征, 即定时弹窗实现的锁机功能
        boolean getContinue1 = methods.contains("AlertDialog.Builder;->setCancelable");
        boolean getContinue2 = methods.contains("Landroid/app/AlertDialog$Builder;->setCancelable");
        boolean getContinue3 = methods.contains("Landroid/app/Dialog;->setCancelable");
        boolean getContinue4 = methods.contains("Landroid/app/AlertDialog;->setCancelable");
        boolean getContinue5 = methods.contains("Landroid/support/v4/app/DialogFragment;->setCancelable");
        boolean getContinue6 = methods.contains("Landroid/support/v7/app/AlertDialog$Builder;->setCancelable");
        if (getContinue1 || getContinue2 || getContinue3 || getContinue4 || getContinue5 || getContinue6) {
            potential_misBhve.add("ContinueWindow");
        }

        // 出自论文的A类加密, 4.2节 加密中第一类方法, 论文出自 http){//cjc.ict.ac.cn/online/bfpub/wch-20171229104205.pdf
//        boolean getData1 = methods.contains("Landroid/content/Intent;->addCategory");
//        boolean getData2 = methods.contains("Landroid/content/Intent;->createChooser");
//        boolean getFileOp1 = methods.contains("Ljava/io/FileInputStream;->");
//        boolean getFileOp2 = methods.contains("Ljava/io/FileOutputStream;->");
//        boolean getFileOp3 = methods.contains("Ljava/io/InputStream;->");
//        boolean getFileOp4 = methods.contains("Ljava/io/OutputStream;->");
//        boolean getDel = methods.contains("Ljava/io/File;->delete");

                boolean getData1 = map_mali_API.containsKey("Landroid/content/Intent;") && map_mali_API.containsKey("addCategory");
        boolean getData2 = map_mali_API.containsKey("Landroid/content/Intent;") && map_mali_API.containsKey("createChooser");
        boolean getFileOp1 = map_mali_API.containsKey("Ljava/io/FileInputStream;");
        boolean getFileOp2 = map_mali_API.containsKey("Ljava/io/FileOutputStream;");
        boolean getFileOp3 = map_mali_API.containsKey("Ljava/io/InputStream;");
        boolean getFileOp4 = map_mali_API.containsKey("Ljava/io/OutputStream;");
        boolean getDel = map_mali_API.containsKey("Ljava/io/File;") && map_mali_API.containsKey("delete");
        if (getData1 && getData2 && (Cipher_getInstance && Cipher_init && Cipher_doFinal) && SecretKeySpec_init
                || IvParameterSpec && writeSD  && mount  && (getFileOp1 && getFileOp2 && getFileOp3 && getFileOp4)) {
            potential_misBhve.add("crypto_A");
        }

        // 出自论文的B类加密, 论文同上, 4.2节 加密中第三类方法
        if ((getFileOp1 && getFileOp2 && cipherOutputStream) && writeSD  && Cipher_getInstance && Cipher_init && SecretKeySpec_init && IvParameterSpec && getDel) {
            potential_misBhve.add("crypto_B");
        }

        // 获取用户的手机号码
//        boolean getLinenum = methods.contains("Landroid/telephony/TelephonyManager;->getLine1Number");
        boolean getLinenum = map_mali_API.containsKey("Landroid/telephony/TelephonyManager;") && map_mali_API.containsKey("getLine1Number");
        if ((Context_getSystemService || ContextWrapper_getSystemService || view_ContextThemeWrapper_getSystemService ||        v7_ContextThemeWrapper_getSystemService) && getLinenum){
            potential_misBhve.add("Get User Phone Number");
        }

        // 获取来信号码
//        boolean getori1 = methods.contains("Landroid/telephony/gsm/SmsMessage;->getoriginatingAddress");
//        boolean getori2 = methods.contains("Landroid/telephony/SmsMessage;->getoriginatingAddress");
//        boolean getori3 = methods.contains("Landroid/telephony/SmsMessage;->getDisplayoriginatingAddress");

                boolean getori1 = map_mali_API.containsKey("Landroid/telephony/gsm/SmsMessage;") && map_mali_API.containsKey("getoriginatingAddress");
        boolean getori2 =map_mali_API.containsKey("Landroid/telephony/SmsMessage;") && map_mali_API.containsKey("getoriginatingAddress");
        boolean getori3 = map_mali_API.containsKey("Landroid/telephony/SmsMessage;") && map_mali_API.containsKey("getDisplayoriginatingAddress");
        if (getori1 || getori2 || getori3) {
            potential_misBhve.add("Get originating address (Sender) of SMS Message");
        }

        // 获取短信内容
//        boolean getMess1 = methods.contains("android.telephony.gsm.SmsMessage;->getMessageBody");
//        boolean getMess2 = methods.contains("Landroid/telephony/SmsMessage;->getMessageBody");
//        boolean getMess3 = methods.contains("Landroid/telephony/SmsMessage;->getDisplayMessageBody");

                boolean getMess1 = map_mali_API.containsKey("android.telephony.gsm.SmsMessage;") && map_mali_API.containsKey("getMessageBody");
        boolean getMess2 = map_mali_API.containsKey("Landroid/telephony/SmsMessage;") && map_mali_API.containsKey("getMessageBody");
        boolean getMess3 = map_mali_API.containsKey("Landroid/telephony/SmsMessage;") && map_mali_API.containsKey("getDisplayMessageBody");
        if (getMess1 || getMess2 || getMess3) {
            potential_misBhve.add("Get Message Body");
        }

        // 发送短信操作
//        boolean getSend1 = methods.contains("android.telephony.SmsManager;->sendTextMessage");
//        boolean getSend2 = methods.contains("android.telephony.SmsManager;->sendMultipartTextMessage");
//        boolean getSend3 = methods.contains("android.telephony.SmsManager;->sendTextMessageWithoutPersisting");
//        boolean getSend4 = methods.contains("android.telephony.gsm.SmsManager;->sendTextMessage");
//        boolean getSend5 = methods.contains("android.telephony.gsm.SmsManager;->sendMultipartTextMessage");

                boolean getSend1 = map_mali_API.containsKey("android.telephony.SmsManager;") && map_mali_API.containsKey("sendTextMessage");
        boolean getSend2 = map_mali_API.containsKey("android.telephony.SmsManager;") && map_mali_API.containsKey("sendMultipartTextMessage");
        boolean getSend3 = map_mali_API.containsKey("android.telephony.SmsManager;") && map_mali_API.containsKey("sendTextMessageWithoutPersisting");
        boolean getSend4 = map_mali_API.containsKey("android.telephony.gsm.SmsManager;") && map_mali_API.containsKey("sendTextMessage");
        boolean getSend5 = map_mali_API.containsKey("android.telephony.gsm.SmsManager;") && map_mali_API.containsKey("sendMultipartTextMessage");
        if (getSend1 || getSend2 || getSend3 || getSend4 || getSend5) {
            potential_misBhve.add("Send SMS");
        }

        // 获取正在运行的应用操作
//        boolean getActivate1 = methods.contains("Landroid/app/ActivityManager;->getRunningAppProcesses");
//        boolean getActivate2 = methods.contains("Landroid/app/ActivityManager;->getRunningTasks");

                boolean getActivate1 = map_mali_API.containsKey("Landroid/app/ActivityManager;") && map_mali_API.containsKey("getRunningAppProcesses");
        boolean getActivate2 = map_mali_API.containsKey("Landroid/app/ActivityManager;") && map_mali_API.containsKey("getRunningTasks");
        if (getActivate1 || getActivate2) {
            potential_misBhve.add("Get Apps running");
        }

        // 隐藏图标操作, 拦截马特征
//        boolean getHideIcon = methods.contains("Landroid/content/pm/PackageManager;->setComponentEnabledSetting");
        boolean getHideIcon = map_mali_API.containsKey("Landroid/content/pm/PackageManager;") && map_mali_API.containsKey("setComponentEnabledSetting");
        if (getHideIcon) {
            potential_misBhve.add("Hide the Icon");
        }

        // 国产锁机特征
        if (getLogcat) {
            potential_misBhve.add("LogCatBroadcaster");
        }

        // 国产锁机特征
        if (getADRT) {
            potential_misBhve.add("ADRTLogCatReader");
        }

        // 防止进程被杀死
        boolean getSF = methods.contains("Landroid/app/Service;->startForeground");
        boolean getSFF1 = methods.contains("Landroid/app/Service;->stopForeground");
        boolean getSFF2 = methods.contains("Landroid/support/v4/app/ServiceCompat;->stopForeground");
        if (getSF && (getSFF1 || getSFF2)) {
            potential_misBhve.add("Avoid service be killed");
        }

        // 查询数据库
        boolean getQuery1 = methods.contains("Landroid/database/sqlite/SQLiteDatabase;->query");
        boolean getQuery2 = methods.contains("Landroid/content/ContentResolver;->query");
        boolean getQuery3 = methods.contains("Landroid/content/ContentProviderClient;->query");
        boolean getQuery4 = methods.contains("Landroid/content/ContentProvider;->query");
        boolean getQuery5 = methods.contains("Landroid/support/v4/content/ContentResolverCompat;->query");
        boolean getQuery6 = methods.contains("Landroid/support/v4/content/FileProvider;->query");
        if (getQuery1 || getQuery2 || getQuery3 || getQuery4 || getQuery5 || getQuery6) {
            potential_misBhve.add("Query the Database");
        }

        // 向数据库插入内容
        boolean getInsert1 = methods.contains("Landroid/database/sqlite/SQLiteDatabase;->insert");
        boolean getInsert2 = methods.contains("Landroid/content/ContentResolver;->insert");
        boolean getInsert3 = methods.contains("Landroid/content/ContentProviderClient;->insert");
        boolean getInsert4 = methods.contains("Landroid/content/ContentProvider;->insert");
        boolean getInsert5 = methods.contains("Landroid/support/v4/content/FileProvider;->insert");
        if (getInsert1 || getInsert2 || getInsert3 || getInsert4 || getInsert5) {
            potential_misBhve.add("Insert the Database");
        }

        // 发送邮件
        boolean getEmail = methods.contains("Ljavax/mail/Transport;->send");
        if (getEmail) {
            potential_misBhve.add("Send the Email");
        }

        // 使用TCP, 进行网络链接
//        boolean openTCP = methods.contains("Ljava/net/Socket;->Socket");
//        boolean getOS1 = methods.contains("Ljava/net/Socket;->getOutputStream");
//        boolean getOS2 = methods.contains("Landroid/net/LocalSocket;->getOutputStream");
//        boolean ServerSocket = methods.contains("Ljava/net/ServerSocket;->ServerSocket");
//        boolean getIS1 = methods.contains("Ljava/net/ServerSocket;->getInputStream");
//        boolean getIS2 = methods.contains("Landroid/net/LocalSocket;->getInputStream");

                boolean openTCP = map_mali_API.containsKey("Ljava/net/Socket;") && map_mali_API.containsKey("Socket");
        boolean getOS1 = map_mali_API.containsKey("Ljava/net/Socket;") && map_mali_API.containsKey("getOutputStream");
        boolean getOS2 = map_mali_API.containsKey("Landroid/net/LocalSocket;") && map_mali_API.containsKey("getOutputStream");
        boolean ServerSocket = map_mali_API.containsKey("Ljava/net/ServerSocket;") && map_mali_API.containsKey("ServerSocket");
        boolean getIS1 = map_mali_API.containsKey("Ljava/net/ServerSocket;") && map_mali_API.containsKey("getInputStream");
        boolean getIS2 = map_mali_API.containsKey("Landroid/net/LocalSocket;") && map_mali_API.containsKey("getInputStream");
        if (openTCP || getOS1 || getOS2 || ServerSocket || getIS1 || getIS2) {
            potential_misBhve.add("Use TCP");
        }

        // 获取手机中已安装的应用
//        boolean getIP = methods.contains("Landroid/content/pm/PackageManager;->getInstalledPackages");
        boolean getIP = map_mali_API.containsKey("Landroid/content/pm/PackageManager;") && map_mali_API.containsKey("getInstalledPackages");
        if (getIP) {
            potential_misBhve.add("Get Apps installed");
        }

        // 使用反射, 通过反射执行某些操作
//        boolean reflect_forName = methods.contains("Ljava/lang/Class;->forName");
//        boolean reflect_getClass = methods.contains("Ljava/lang/Object;->getClass");
//        boolean invoke = methods.contains("Ljava/lang/reflect/Method;->invoke");

                boolean reflect_forName = map_mali_API.containsKey("Ljava/lang/Class;") && map_mali_API.containsKey("orName");
        boolean reflect_getClass = map_mali_API.containsKey("Ljava/lang/Object;") && map_mali_API.containsKey("getClass");
        boolean invoke = map_mali_API.containsKey("Ljava/lang/reflect/Method;") && map_mali_API.containsKey("invoke");
        if ((reflect_forName || reflect_getClass) && invoke) {
            potential_misBhve.add("Use Reflect");
        }

        // 使用动态加载
//        boolean dynamic_load = methods.contains("Ldalvik/system/DexClassLoader;-><init>");
//        boolean load_class = methods.contains("Ldalvik/system/DexClassLoader;->loadClass");

                boolean dynamic_load = map_mali_API.containsKey("Ldalvik/system/DexClassLoader;");
        boolean load_class =map_mali_API.containsKey("Ldalvik/system/DexClassLoader;") && map_mali_API.containsKey("loadClass");
        if (dynamic_load || load_class) {
            potential_misBhve.add("Use Dynamic Load");
        }

        // 加载写在 so 文件中的 native 库
        boolean native_code = methods.contains("Ljava/lang/System;->loadLibrary");
        if (native_code) {
            potential_misBhve.add("Load native library");
        }

        // 切分短信，拦截马特征
        boolean divide_message1 = methods.contains("Landroid/telephony/SmsManager;->divideMessage");
        boolean divide_message2 = methods.contains("Landroid/telephony/gsm/SmsManager;->divideMessage");
        if (divide_message1 || divide_message2) {
            potential_misBhve.add("divide the message");
        }

        // 第二种设置默认短信应用, 即实现方式不同
//        boolean getDSM = methods.contains("Landroid/provider/Telephony$Sms;->getDefaultSmsPackage");
        boolean getDSM = map_mali_API.containsKey("Landroid/provider/Telephony$Sms;") && map_mali_API.containsKey("getDefaultSmsPackage");
        if (getDSM && actionCC) {
            potential_misBhve.add("Set default SMS app");
        }

        // 更新短信数据库的内容
//        boolean SMSStatusUpdate1 = methods.contains("Landroid/content/ContentResolver;->update");
//        boolean SMSStatusUpdate2 = methods.contains("Landroid/content/ContentProvider;->update");
//        boolean SMSStatusPut = methods.contains("Landroid/content/ContentValues;->put");

                boolean SMSStatusUpdate1 = map_mali_API.containsKey("Landroid/content/ContentResolver;") && map_mali_API.containsKey("update");
        boolean SMSStatusUpdate2 = map_mali_API.containsKey("Landroid/content/ContentProvider;") && map_mali_API.containsKey("update");
        boolean SMSStatusPut = map_mali_API.containsKey("Landroid/content/ContentValues;") && map_mali_API.containsKey("put");
        if ((SMSStatusUpdate1 || SMSStatusUpdate2) && SMSStatusPut) {
            potential_misBhve.add("Update SMS status");
        }

        // 重复启动应用, 定时任务, 通过隐式 intent 启动
//        boolean AlarmManagerRepeating = methods.contains("Landroid/app/AlarmManager;->setRepeating");
//        boolean getBroadcast = methods.contains("Landroid/app/PendingIntent;->getBroadcast");

                boolean AlarmManagerRepeating = map_mali_API.containsKey("Landroid/app/AlarmManager;") && map_mali_API.containsKey("setRepeating");
        boolean getBroadcast = map_mali_API.containsKey("Landroid/app/PendingIntent;") && map_mali_API.containsKey("getBroadcast");
        if (AlarmManagerRepeating && getSystemService && getBroadcast) {
            potential_misBhve.add("Set app start repeatly");
        }

        // 获取resources对象, 访问应用程序中存在的文件资源
//        boolean getResourceAsStream = methods.contains("Ljava/lang/Class;->getResourceAsStream");
        boolean getResourceAsStream = map_mali_API.containsKey("Ljava/lang/Class;") && map_mali_API.containsKey("getResourceAsStream");
        if (getResources || getResourceAsStream) {
            potential_misBhve.add("Get Resources");
        }

        // 使用 Webview 进行网络访问
//        boolean webView = methods.contains("Landroid/webkit/WebViewClient;-><init>");
        boolean webView = map_mali_API.containsKey("Landroid/webkit/WebViewClient;");
        if (webView) {
            potential_misBhve.add("Use WebView");
        }

        // 获取 SIM 卡信息 以及网络状态
//        boolean SimInfo = methods.contains("Landroid/telephony/TelephonyManager;->getNetworkOperator");
//        boolean SimInfo_2 = methods.contains("Landroid/telephony/TelephonyManager;->getSimOperator");
//        boolean SimInfo_3 = methods.contains("Landroid/telephony/TelephonyManager;->getSubscriberId");

                boolean SimInfo = map_mali_API.containsKey("Landroid/telephony/TelephonyManager;") && map_mali_API.containsKey("getNetworkOperator");
        boolean SimInfo_2 = map_mali_API.containsKey("Landroid/telephony/TelephonyManager;") && map_mali_API.containsKey("getSimOperator");
        boolean SimInfo_3 = map_mali_API.containsKey("Landroid/telephony/TelephonyManager;") && map_mali_API.containsKey("getSubscriberId");
        if (SimInfo || SimInfo_2 || SimInfo_3) {
            potential_misBhve.add("Get SIM Information");
        }

        // 获取 MCC && MNC
        boolean MCC_MNC = methods.contains("Ljava/lang/String;->substring");
        if ((SimInfo || SimInfo_2 || SimInfo_3) && MCC_MNC) {
            potential_misBhve.add("Get MCC && MNC");
        }


        // 对配置文件执行操作, 比如修改读取等
        boolean getSharedPreferences = methods.contains("Landroid/content/Context;->getSharedPreferences");
        boolean EditSharedPreferences = methods.contains("Landroid/content/SharedPreferences;->edit");
        boolean CommitSharedPreferences = methods.contains("Landroid/content/SharedPreferences$Editor;->commit");
        if (getSharedPreferences && EditSharedPreferences && CommitSharedPreferences) {
            potential_misBhve.add("Configuration File Operations");
        }


        // 删除短信
//        boolean DeleteSMS = methods.contains("Landroid/content/ContentResolver;->delete");
        boolean DeleteSMS = map_mali_API.containsKey("Landroid/content/ContentResolver;") && map_mali_API.containsKey("delete");
        if (DeleteSMS) {
            potential_misBhve.add("Delete SMS");
        }
        // 申请权限, 会在最上层显示应用
        //         addView = methods.contains(";->addView");
//        boolean addView = methods.contains("Landroid/view/WindowManager;->addView");
        boolean addView = map_mali_API.containsKey("Landroid/view/WindowManager;") && map_mali_API.containsKey("addView");
        if (addView && alertWindow) {
            potential_misBhve.add("alertWindow");
        }
        // 根据类型获取设备上的账号
        boolean getAccountsByType = methods.contains("Landroid/accounts/AccountManager;->getAccountsByType");
        if (getAccountsByType) {
            potential_misBhve.add("getAccountsByType");
        }

        // 获取进程对内存的使用大小
//        boolean getProcessMemoryInfo = methods.contains("Landroid/app/ActivityManager;->getProcessMemoryInfo");
        boolean getProcessMemoryInfo = map_mali_API.containsKey("Landroid/app/ActivityManager;") && map_mali_API.containsKey("getProcessMemoryInfo");
        if (getProcessMemoryInfo) {
            potential_misBhve.add("getProcessMemoryInfo");
        }

        // 重写"用户申请取消设备管理器权限时所调用的方法"
//        boolean  onDisableRequested = methods.contains("Landroid/app/admin/DeviceAdminReceiver;->onDisableRequested");
        boolean  onDisableRequested = map_mali_API.containsKey("Landroid/app/admin/DeviceAdminReceiver;") && map_mali_API.containsKey("onDisableRequested");
        if (onDisabled || onDisableRequested) {
            potential_misBhve.add("awareDeviceAdminDisable");
        }

        // 设置铃声模式, 比如静音, 震动等
//        boolean  setRingerMode = methods.contains("Landroid/media/AudioManager;->setRingerMode");
        boolean  setRingerMode = map_mali_API.containsKey("Landroid/media/AudioManager;") && map_mali_API.containsKey("setRingerMode");
        if (setRingerMode) {
            potential_misBhve.add("setRingerMode");
        }

        // 查询数据库（system preferences）
//        boolean getString = methods.contains("Landroid/provider/Settings$Secure;->getString");
        boolean getString = map_mali_API.containsKey("Landroid/provider/Settings$Secure;") && map_mali_API.containsKey("getString");
        if (getString) {
            potential_misBhve.add("getString");
        }

        // 获取editText内容（可能是勒索类应用要求用户输入密码的地方）
        boolean getText = methods.contains("Landroid/widget/EditText;->getText");
        // 判断文本是否相同
        boolean equals = methods.contains("Ljava/lang/String;->equals");
        if (getText && equals) {
            potential_misBhve.add("getText_and_equals");
        }
        // 使用 http 网络服务
//        boolean HttpURLConnection_connect = methods.contains("Ljava/net/HttpURLConnection;->connect");
//        boolean HttpURLConnection_getOutputStream = methods.contains("Ljava/net/HttpURLConnection;->getOutputStream");
//        boolean HttpURLConnection_getInputStream = methods.contains("Ljava/net/HttpURLConnection;->getInputStream");

                boolean HttpURLConnection_connect = map_mali_API.containsKey("Ljava/net/HttpURLConnection;") && map_mali_API.containsKey("connect");
        boolean HttpURLConnection_getOutputStream = map_mali_API.containsKey("Ljava/net/HttpURLConnection;") && map_mali_API.containsKey("getOutputStream");
        boolean HttpURLConnection_getInputStream = map_mali_API.containsKey("Ljava/net/HttpURLConnection;") && map_mali_API.containsKey("getInputStream");
        if (HttpURLConnection_connect || HttpURLConnection_getOutputStream) {
            potential_misBhve.add("Use HttpURLConnection");
        }
        // 发送 http 网络请求
        if (HttpURLConnection_getInputStream){
            potential_misBhve.add("Send HttpURLConnection request");
        }

        // 获取 http 响应
//        boolean DefaultHttpClient_execute = methods.contains("Lorg/apache/http/impl/client/DefaultHttpClient;->execute");
//        boolean HttpResponse_getEntity = methods.contains("Lorg/apache/http/HttpResponse;->getEntity");

                boolean DefaultHttpClient_execute = map_mali_API.containsKey("Lorg/apache/http/impl/client/DefaultHttpClient;") && map_mali_API.containsKey("execute");
        boolean HttpResponse_getEntity = map_mali_API.containsKey("Lorg/apache/http/HttpResponse;") && map_mali_API.containsKey("getEntity");
        if (DefaultHttpClient_execute && HttpResponse_getEntity){
            potential_misBhve.add("Get Http Response");
        }

        // 获取正在运行的 service
        boolean getRunningServices = methods.contains("Landroid/app/ActivityManager;->getRunningServices");
        boolean queryUsageStats = methods.contains("Landroid/app/usage/UsageStatsManager;->queryUsageStats");
        boolean topPackageName = methods.contains("Landroid/content/Context;->getPackageName");
        if ((Context_getSystemService || ContextWrapper_getSystemService || view_ContextThemeWrapper_getSystemService ||
        v7_ContextThemeWrapper_getSystemService) && (
                getRunningServices || (queryUsageStats && topPackageName))){
            potential_misBhve.add("Get Running Services");
        }

        // 通过资源对象访问应用中的资源文件
//        boolean openRawResource = methods.contains("Landroid/content/res/Resources;->openRawResource");
        boolean openRawResource = map_mali_API.containsKey("Landroid/content/res/Resources;") && map_mali_API.containsKey("openRawResource");
        if (getResources && openRawResource){
            potential_misBhve.add("Get Resource From Raw File");
        }

        // 读取资源文件
//        boolean InputStreamReader = methods.contains("Ljava/io/InputStreamReader");
        boolean InputStreamReader = map_mali_API.containsKey("Ljava/io/InputStreamReader");
        if (getResources && openRawResource && InputStreamReader){
            potential_misBhve.add("Read Raw File");
        }

        // 设置 UI 的可见度
//        boolean setVisibility = methods.contains("Landroid/view/View;->setVisibility");
        boolean setVisibility = map_mali_API.containsKey("Landroid/view/View;") && map_mali_API.containsKey("setVisibility");
        if (setVisibility){
            potential_misBhve.add("Set UI Visibility");
        }

        // 包含多个字符串，比如 sdk 版本
//        boolean BuildVersion = methods.contains("Landroid/os/Build$VERSION");
        boolean BuildVersion = map_mali_API.containsKey("Landroid/os/Build$VERSION");
        if (BuildVersion){
            potential_misBhve.add("Get Build Version");
        }

        // 获取 SharedPreferences 文件中的属性值
//        boolean SharedPreferences_getAll = methods.contains("Landroid/content/SharedPreferences;->get*");
        boolean SharedPreferences_getAll =false;
        for(Object m:methods){
            if(m.toString().startsWith("Landroid/content/SharedPreferences;->get")){
                SharedPreferences_getAll=true;
                break;
            }
        }
        if (SharedPreferences_getAll){
            potential_misBhve.add("Get attribute from SharedPreferences");
        }

        // 取消定时任务
//        boolean AlarmManager_cancel = methods.contains("Landroid/app/AlarmManager;->cancel");
        boolean AlarmManager_cancel = map_mali_API.containsKey("Landroid/app/AlarmManager;") && map_mali_API.containsKey("cancel");
        if (AlarmManager_cancel){
            potential_misBhve.add("Cancel Alarm");
        }

        // 使用多线程服务
//        boolean Thread_init = methods.contains("Ljava/lang/Thread;-><init>");
//        boolean Thread_start = methods.contains("Ljava/lang/Thread;->start");
                boolean Thread_init = map_mali_API.containsKey("Ljava/lang/Thread;");
        boolean Thread_start = map_mali_API.containsKey("Ljava/lang/Thread;") && map_mali_API.containsKey("start");
        if (Thread_init && Thread_start){
            potential_misBhve.add("Use Thread");
        }

        // 使用代理
//        boolean Proxy_getDefaultHost = methods.contains("Landroid/net/Proxy;->getDefaultHost");
//        boolean Proxy_getDefaultPort = methods.contains("Landroid/net/Proxy;->getDefaultPort");

                boolean Proxy_getDefaultHost = map_mali_API.containsKey("Landroid/net/Proxy;") && map_mali_API.containsKey("getDefaultHost");
        boolean Proxy_getDefaultPort = map_mali_API.containsKey("Landroid/net/Proxy;") && map_mali_API.containsKey("getDefaultPort");
        if (Proxy_getDefaultHost && Proxy_getDefaultPort){
            potential_misBhve.add("Use Proxy");
        }

        // 微信支付 SDK　使用
        boolean wechat_pay1 = methods.contains("Lcom/tencent/mm/sdk/openapi/WXAPIFactory;->createWXAPI");
        boolean wechat_pay2 = methods.contains("Lcom/tencent/mm/sdk/openapi/WXApiImplV10;->registerApp");
        boolean wechat_pay3 = methods.contains("Lcom/tencent/mm/sdk/openapi/WXApiImplV10;->sendReq");
        boolean wechat_pay4 = methods.contains("Lcom/tencent/mm/sdk/openapi/IWXAPIEventHandler;->onResp");
        if (wechat_pay1 || wechat_pay2 || wechat_pay3 || wechat_pay4){
            potential_misBhve.add("WeChat Pay");
        }

        // 咪咕支付 SDK 使用
//        boolean migu_pay1 = methods.contains("Lcn/cmgame/billing/api/GameInterface;->initializeApp");
//        boolean migu_pay2 = methods.contains("Lcn/cmgame/billing/api/GameInterface;->doBilling");

                boolean migu_pay1 = map_mali_API.containsKey("Lcn/cmgame/billing/api/GameInterface;") && map_mali_API.containsKey("initializeApp");
        boolean migu_pay2 = map_mali_API.containsKey("Lcn/cmgame/billing/api/GameInterface;") && map_mali_API.containsKey("doBilling");
        if (migu_pay1 || migu_pay2){
            potential_misBhve.add("MiGu Pay");
        }

        // 转发短信
        if(potential_misBhve.contains("Get Message Body") && potential_misBhve.contains("Send SMS")){
            for(String s:suspicious_keywords_Equal){
                if(s.equals("pdus")){
                    potential_misBhve.add("Forward SMS");
                    break;
                }
            }
        }

        // 通过包名启动应用指定的 Activity
//        boolean getLaunchIntentForPackage = methods.contains("Landroid/content/pm/PackageManager;->getLaunchIntentForPackage");
//        boolean startActivity = methods.contains("Lcom/android/append/LauncherActivity;->startActivity");

                boolean getLaunchIntentForPackage = map_mali_API.containsKey("Landroid/content/pm/PackageManager;") && map_mali_API.containsKey("getLaunchIntentForPackage");
        boolean startActivity = map_mali_API.containsKey("Lcom/android/append/LauncherActivity;") && map_mali_API.containsKey("startActivity");
        if (getLaunchIntentForPackage && startActivity){
            potential_misBhve.add("Start Activity via Package name");
        }

        // Java 代码中调用 shell 命令
//        boolean getRuntime = methods.contains("Ljava/lang/Runtime;->getRuntime");
//        boolean exec = methods.contains("Ljava/lang/Runtime;->exec");

                boolean getRuntime = map_mali_API.containsKey("Ljava/lang/Runtime;") && map_mali_API.containsKey("getRuntime");
        boolean exec = map_mali_API.containsKey("Ljava/lang/Runtime;") && map_mali_API.containsKey("exec");
        if (getRuntime && exec){
            potential_misBhve.add("Java Exec Shell cmds");
        }

        // 执行 SQL 命令
//        boolean execSQL = methods.contains("Landroid/database/sqlite/SQLiteDatabase;->execSQL");
        boolean execSQL = map_mali_API.containsKey("Landroid/database/sqlite/SQLiteDatabase;") && map_mali_API.containsKey("execSQL");
        if (execSQL){
            potential_misBhve.add("Exec SQL cmds");
        }

        // 杀死进程操作
//        boolean killProcess = methods.contains("Landroid/os/Process;->killProcess");
//        boolean killBackgroundProcesses = methods.contains("Landroid/app/ActivityManager;->killBackgroundProcesses");

                boolean killProcess = map_mali_API.containsKey("Landroid/os/Process;") && map_mali_API.containsKey("killProcess");
        boolean killBackgroundProcesses = map_mali_API.containsKey("Landroid/app/ActivityManager;") && map_mali_API.containsKey("killBackgroundProcesses");
        if (killBackgroundProcesses || killProcess){
            potential_misBhve.add("Kill Process");
        }
        // 申请设备管理器权限
        boolean device_admin_in_xml = find_string_in_xml("<device-admin");
        if (device_admin_permission && device_admin_in_xml) {
            potential_misBhve.add("Device Admin Permission");
        }


        boolean plankton_service1 = methods.contains("Lcom/apperhand/device/android/androidSDKProvider;->");
        boolean plankton_service2 = methods.contains("Lcom/plankton/device/android/androidMDKProvider;->");
        boolean plankton_service3 = methods.contains("Lcom/plankton/device/android/service/androidMDKService;->");
        if (plankton_service1 || plankton_service2 || plankton_service3) {
            potential_misBhve.add("Plankton Feature");
        }

        boolean setDataandType = methods.contains("Landroid/content/Intent;->setDataandType");
        boolean fromFile = methods.contains("Landroid/net/Uri;->fromFile");
        boolean getExternalStorageDirectory = methods.contains("Landroid/os/Environment;->getExternalStorageDirectory");
        boolean getExternalStoragePublicDirectory = methods.contains("Landroid/os/Environment;->getExternalStoragePublicDirectory");
        if (setDataandType && fromFile && getExternalStorageDirectory) {
            potential_misBhve.add("Mmarket Feature");
        }
        if (setDataandType && fromFile && getExternalStorageDirectory && getExternalStoragePublicDirectory) {
            potential_misBhve.add("Ginmaster Feature");
        }


        if (geinimi_package) {
            potential_misBhve.add("Geinimi Feature");
        }

        boolean voiceMailNumber = methods.contains("Landroid/telephony/TelephonyManager;->getVoiceMailNumber");
        if (voiceMailNumber) {
            potential_misBhve.add("getVoiceMailNumber");
        }

        if (boot && wakeLock){
            potential_misBhve.add("Mixed Feature from SimpleLocker");
        }
        if (boot && wakeLock && alertWindow && getTasks){
            potential_misBhve.add("Mixed Feature from Koler && Roop");
        }
        if (boot && wakeLock && getTasks){
            potential_misBhve.add("Mixed Feature from Aples");
        }
        if (boot && wakeLock && alertWindow){
            potential_misBhve.add("Mixed Feature from Svpeng");
        }

        if (potential_misBhve.contains("Avoid service be killed") && potential_misBhve.contains("Set app start repeatly") && potential_misBhve.contains("alertWindow")
            && potential_misBhve.contains("setSystemWindow") && potential_misBhve.contains("Use Thread")  && potential_misBhve.contains("Kill Process")
            && potential_misBhve.contains("Lock Mixed Feature 3")){
            potential_misBhve.add("Mixed Feature from Koler && Svpeng");
        }
        if (potential_misBhve.contains("alertWindow") && potential_misBhve.contains("setSystemWindow") && potential_misBhve.contains("Use Thread")
                && potential_misBhve.contains("Lock Mixed Feature 3")){
            potential_misBhve.add("Mixed Feature from Roop Congur && Pigetrl");
        }
        if (potential_misBhve.contains("Use Thread") && potential_misBhve.contains("Device Admin Permission") && potential_misBhve.contains("Lock Mixed Feature 2")){
            potential_misBhve.add("Mixed Feature from SimpleLocker && Aples");
        }

        if (http_pay || https_pay){
            potential_misBhve.add("HTTP PAY");
        }
        // WAP扣费，关闭WIFI+打开移动数据网络
        boolean closeWIFI = methods.contains("Landroid/net/wifi/WifiManager;->setWifiEnabled");
        boolean setDataEnabled1 = false;
        boolean declareMethod = methods.contains("Ljava/lang/Class;->getDeclaredMethod");
        boolean setAccessible1 = methods.contains("Ljava/lang/reflect/Field;->setAccessible");
        boolean setAccessible2 = methods.contains("Ljava/lang/reflect/Method;->setAccessible");
        boolean setAccessible3 = methods.contains("Ljava/lang/reflect/Constructor;->setAccessible");
        if ((setDataEnabled || setMobileDataEnabled) && declareMethod && (
                setAccessible3 || setAccessible2 || setAccessible1)) {
            setDataEnabled1 = true;
            boolean loadclass = false;
            boolean loadClass1 = methods.contains("Ljava/lang/ClassLoader;->loadClass");
            boolean loadClass2 = methods.contains("Ldalvik/system/DexClassLoader;->loadClass");
            if (loadClass1 || loadClass2) {
                loadclass = true;
                if (closeWIFI && setDataEnabled1 && loadclass && changeWifi) {
                    potential_misBhve.add("WAP Cost");
                }
            }
        }

        // 11.16 特征来自amd-fakeinst 视为扣费相关
        boolean MessageSender = methods.contains("Lcom/soft/android/appinstaller/MessageSender");
        if (MessageSender){
            potential_misBhve.add("MessageSender Class");
        }

        // 11.16 数组拼接函数名
        boolean Array_Methods = find_suspicious_methods_from_Array();
        if (Array_Methods){
            potential_misBhve.add("SMS from Array_Methods");

        }

        // 12.7 特征来自plankton远控家族
        if (searchmobileonline){
            potential_misBhve.add("plankton searchmobileonline");
        }


        if (BOOKMARKS && SHORTCUTS && COMMANDS_STATUS && ACTIVATION  && TERMINATE && UNEXPECTED_EXCEPTION && INFO) {
            potential_misBhve.add("plankton 7 commands");
        }

        // 检测abortBroadcast方法，拦截广播
        if (abortBroadcast){
            potential_misBhve.add("abortBroadcast");
        }


        // 屏蔽back键
        if (deny_button1 || deny_button2 || deny_button3 || deny_button4){
            potential_misBhve.add("Deny Back Button");
        }

        return potential_misBhve;
    }

    public Map<String,String> get_time(){
        /***    获取 APK 文件的最后更改时间**/
        String cmd="ls -l "+apkSourceURI;
        Map<String,String> Time=new HashMap<>();
//        try {
//            Process process= Runtime.getRuntime().exec(cmd);
//            BufferedReader bufferedReader = new BufferedReader( new InputStreamReader(process.getInputStream()), 1024);
//            String line = bufferedReader.readLine();
//            String[] sub=line.split("-");
//            String Y=sub[0].
//            Time.put("year",);
//            Time.put("month","0");
//            Time.put("day","0");
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
        Time.put("year","0");
        Time.put("month","0");
        Time.put("day","0");
        return Time;
    }

    public Boolean find_suspicious_methods_from_Array(){
        /***    用来查找是否存在数组混淆*/
        return false;
    }

    public boolean find_string_in_xml(String s){
        /***    在.xml文件中查找字符串s*/
        return false;
    }

    public String detect_app_name_language(){
        /** 获取应用名称的语言.参看：http://bbs.bugcode.cn/t/119691
         :return: 语言类别**/
        String language = "Unknown";
        try {
            // Prepare the profile before
            DetectorFactory.loadProfile("/language-detection/profiles");
            // Create the Detector
            Detector d = DetectorFactory.create();
            d.append(appName);
            language=d.detect(); // Ouput: "fr"
        } catch (LangDetectException e) {
            e.printStackTrace();
        }
        return language;
    }


    public boolean is_mismatch_components_and_package(){
       /** 判断 APK 中各组件的前缀是否与包名一致 */
       /*** 返回true，说明存在组件的前缀与包名不一致；返回false，说明都一致*/
       String conpName=null;
       if(activities!=null){
           for (Object a:activities){
               conpName=a.toString();
               if(!conpName.startsWith(pkgName)){
                   return true;
               }
           }
       }
       if(services!=null){
           for (Object s:services){
               conpName=s.toString();
               if(!conpName.startsWith(pkgName)){
                   return true;
               }
           }
       }
       if(providers!=null){
           for(Object p:providers){
               conpName=p.toString();
               if(!conpName.startsWith(pkgName)){
                   return true;
               }
           }
       }
       return false;
    }


    public double entropy(){
        /** 通过字符串计算该字符串的熵.未参考python版特征提取，而是参考：https://blog.csdn.net/fjssharpsword/article/details/53994179
         */
        double H = .0;
        int sum = 0;
        int[] letter = new int[26];//26个字符
        String str = pkgName.toUpperCase(); // 将小写字母转换成大写
        for (int i = 0; i < str.length(); i++) { // 统计字母个数
            char c = str.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                letter[c - 'A']++;
                sum++;
            }
        }
        //计算信息熵，将字母出现的频率作为离散概率值
        for (int i = 0; i < 26; i++) {
            double p = 1.0 * letter[i] / sum;//单个字母的频率
            if (p > 0)
                H += -(p * Math.log(p) / Math.log(2));// H = -∑Pi*log2(Pi)
        }
        return H;
    }


    public boolean hasMultiDEX(){
        /***    判断是否包含多个dex文件*/
        lanchon.multidexlib2.BasicDexFileNamer v6_1 = new lanchon.multidexlib2.BasicDexFileNamer();
        List<String> entryNames=null;
        try {
            if (f.isDirectory()) {
                lanchon.multidexlib2.DirectoryDexContainer v3 = null;
                v3 = new lanchon.multidexlib2.DirectoryDexContainer(f, ((lanchon.multidexlib2.DexFileNamer) v6_1), null);
                entryNames = v3.getDexEntryNames();
                if (entryNames.size() > 1) {
                    return true;
                }
            } else if (lanchon.multidexlib2.ZipFileDexContainer.isZipFile(f)) {
                lanchon.multidexlib2.ZipFileDexContainer v3_1 = new lanchon.multidexlib2.ZipFileDexContainer(f, ((lanchon.multidexlib2.DexFileNamer) v6_1), null);
                entryNames = v3_1.getDexEntryNames();
                if (entryNames.size() > 1) {
                    return true;
                }
            } else if (f.isFile()) {
                lanchon.multidexlib2.SingletonDexContainer v3_2 = new lanchon.multidexlib2.SingletonDexContainer(lanchon.multidexlib2.RawDexIO.readRawDexFile(f, null));
                entryNames = v3_2.getDexEntryNames();
                if (entryNames.size() > 1) {
                    return true;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }
//    public ArrayList<String> get_intents_in_code(){
//        /***获取在代码中动态申请的 intent */
//        ArrayList intents_in_code=new ArrayList();
//        String s;
//        Iterator<DexBackedStringReference> iterator =z_Strings.iterator();
//        while (iterator.hasNext()) {
//            DexBackedStringReference current = iterator.next();
//            s=current.getString();
//            if(s.contains("android.provider") || s.contains("android.intent")){
//                intents_in_code.add(s);
//            }
//        }
//        return intents_in_code;
//    }


    public void hasVideoOrHTML(){
        /***判断 APK 文件中是否包含 视频文件*/
        String[] video_types = new String[]{".avi", ".mp3", ".mp4", ".flv", ".mkv", ".gif", ".wmv", "rmvb", ".m4p", ".3gp"};
        String [] HTMLDocumentTypes = new String[]{".js", ".html", ".css"};
        ArrayList feature_files = new ArrayList();
        String [] FakeInstallerFiles = new String[]{"adata.dat", "bdata.dat","data.dat", "wdata.dat"};
        try {
            ZipFile zf =new ZipFile(f);
            InputStream in =new BufferedInputStream(new FileInputStream(f));
            ZipInputStream zin =new ZipInputStream(in);
            ZipEntry ze;
            String mFileData ="";
            String line ="";
            String name=null;
            String subString=null;
            int len=0;
            while ((ze =zin.getNextEntry()) !=null) {
                if (!ze.isDirectory()){
                    name=ze.getName();
                    len=name.length();
                    if(!hasVideo){
                        for(String s:video_types){
                            subString=name.substring(len-5,len);
                            if(subString.contains(s)){
                                hasVideo=true;
                                break;
                            }
                        }
                    }
                    if(!hasHTMLDocuments){
                        for(String h:HTMLDocumentTypes){
                            subString=name.substring(len-6,len);
                            if(subString.contains(h)){
                                hasHTMLDocuments=true;
                                break;
                            }
                        }
                    }
                    if(!hasFakeInstaller3or4Files){
                        for(String f:FakeInstallerFiles){
                            if(name.contains(f) && !feature_files.contains(name)){
                                feature_files.add(name);
                            }
                            if(feature_files.size()>=3){
                                hasFakeInstaller3or4Files=true;
                                break;
                            }
                        }
                    }
                    if(name.endsWith(".so")){
                        so_files.add(name);
                    }
                }

            }
            zin.closeEntry();
            in.close();
            } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public long getFileSize(){
        long tmp=this.f.getTotalSpace()/(1024 * 1024);
        tmp=tmp/(100000*5);
        return tmp;// python 版：round(os.path.getsize(self.path) / (1024 * 1024), round_num)
    }


    public  Boolean   detect_email(String s) {
        /**检测匹配 email*/
        if(s.length()>7){
            Pattern p = Pattern.compile("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$");
            Matcher m = p.matcher(s);
            if(m.matches() ) {
                return true;
            }
        }
        return false;
    }

//    public ArrayList<String>   get_suspicious_emails(){
//        /**    匹配 APK 文件中字符串中出现的 邮箱号码***/
//        ArrayList<String> emailList=new ArrayList<>();
//        String s=null;
//        Iterator<DexBackedStringReference> iterator =z_Strings.iterator();
//        while (iterator.hasNext()) {
//            DexBackedStringReference current = iterator.next();
//            s=current.getString();
//            if(detect_email(s)){
//                emailList.add(s);
//            }
//        }
//        return emailList;
//    }
    public  Boolean  detect_phone(String s) {
            /****检测匹配手机号码*/
            String[] phoneprefix = new String[]{"130", "131", "132", "133", "134", "135", "136", "137", "138", "139", "150", "151", "152", "153",
                "155", "156", "157", "158", "159", "170", "183", "182", "185", "186", "187", "188", "189"};
            if(s.length()==11){
                Pattern p = Pattern.compile("[0-9]*");
                Matcher m = p.matcher(s);
                if(m.matches() ){
                    String refix=s.substring(0,3);
                    for(String pr:phoneprefix){
                        if(pr.equals(refix)){
                            return true;
                        }
                    }
                }
            }
            return false;
    }


//    public ArrayList<String>   get_suspicious_phones(){
//        /**    匹配 APK 文件中字符串中出现的 手机号码
//         备注： 仅支持国内手机号***/
//        ArrayList<String> phoneList=new ArrayList<>();
//        String s=null;
//        Iterator<DexBackedStringReference> iterator =z_Strings.iterator();
//        while (iterator.hasNext()) {
//            DexBackedStringReference current = iterator.next();
//            s=current.getString();
//            if(detect_phone(s)){
//                phoneList.add(s);
//            }
//        }
//        return phoneList;
//    }


    public  Boolean detect_url(String s) {
        /**判断字符串是否为url格式。没采用特征提取python版，参考了：https://www.jianshu.com/p/4276163968c8  */
        if(s.startsWith("http") || s.startsWith("https") || s.startsWith("ftp")){
            Pattern p = Pattern.compile("((http|ftp|https)://)(([a-zA-Z0-9\\._-]+\\.[a-zA-Z]{2,6})|([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}))(:[0-9]{1,4})*(/[a-zA-Z0-9\\&%_\\./-~-]*)?", Pattern.CASE_INSENSITIVE);
            try {
                Matcher matcher = p.matcher(s);
                matcher.find();
                if(matcher.group().length()>=1){
                    return true;
                }
            }catch (Exception e){
                return false;
            }
        }
        return false;
    }

//    public ArrayList<String>  get_suspicious_urls(){
//        /**    匹配 APK 文件中字符串中出现的 URL
//         :return: 包含 URL 的列表**/
//        ArrayList<String> urlList=new ArrayList<>();
//        String s=null;
//        Iterator<DexBackedStringReference> iterator =z_Strings.iterator();
//        while (iterator.hasNext()) {
//            DexBackedStringReference current = iterator.next();
//            s=current.getString();
//            if(detect_url(s)){
//                urlList.add(s);
//            }
//        }
//        return urlList;
//    }

    public void getPermissions(){
        String[] mPermissions=null;
        try {
            mPermissions=this.packageManager.getPackageInfo(pkgName, PackageManager.GET_PERMISSIONS).requestedPermissions;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        if(mPermissions!=null){
            for(String p:mPermissions){
                if(p!=null){
                    permList.add(p);
                }

            }
        }
    }

    public void   get_suspicious_package_names(){
        /***匹配 APK 文件中出现的 可疑关包名
         备注：包含匹配, 即包名中存在与该可疑包名即可. 为避免可疑包名与其他特征冲突, 每个可疑关键字后面添加后缀 _pkg_name
         :return: 返回出现的可疑包名 的 list*/
        ArrayList<String> package_names =ApkUtil.getClassesA(dexFile);
        String pkg=null;
        for (String s:suspicious_pkg_names){
            if(package_names.contains(s)){
                pkg=s+"_pkg_name";
                if(!pkgList.contains(pkg)){
                    pkgList.add(pkg);
                }
            }
        }
    }


//    public Map<String,Integer>   get_suspicious_keywords_equal(){
//    /***匹配 APK 中 dex 文件中出现的 可疑关键字
//    备注：相等匹配, 即字符串中与该可疑关键字相等才可. 为避免可疑关键字与其他特征冲突, 每个可疑关键字后面添加后缀 _keyword
//        :return: 返回出现的可疑关键字 的 list*/
//        String s=null;
//        Map<String,Integer> keywordsEqualDict=new HashMap<String, Integer>();
//        String k_tmp=null;
//        int c=1;
//        for(String keyword:suspicious_keywords_Equal){
//            if(z_Strings.contains(keyword)){
//                k_tmp=keyword+"_keyword";
//                if(keywordsEqualDict.containsKey(k_tmp)){
//                    c=keywordsEqualDict.get(k_tmp)+1;
//                    keywordsEqualDict.put(k_tmp,c);
//                }else {
//                    keywordsEqualDict.put(k_tmp,1);
//                }
//            }
//        }
//        return keywordsEqualDict;
//    }


//    public Map<String,Integer>  get_suspicious_keywords_in(){
//        /** 匹配 APK 中 dex 文件中出现的 可疑关键字
//         备注：包含匹配, 即字符串中出现该可疑关键字即可. 为避免可疑关键字与其他特征冲突, 每个可疑关键字后面添加后缀 _keyword
//         :return: 返回出现的可疑关键字 的 list*/
//        String s=null;
//        Map<String,Integer> keywordsInDict=new HashMap<String, Integer>();
//        String k_tmp=null;
//        int c=1;
//        for(String keyword:suspicious_keywords_In){
//            for(DexBackedStringReference z:z_Strings){
//                s=z.getString();
//                if(s.contains(keyword)){
//                    k_tmp=keyword+"_keyword";
//                    if(keywordsInDict.containsKey(k_tmp)){
//                        c=keywordsInDict.get(k_tmp)+1;
//                        keywordsInDict.put(k_tmp,c);
//                    }
//                    else {
//                        keywordsInDict.put(k_tmp,1);
//                    }
//                }
//            }
//        }
//        return keywordsInDict;
//    }

    public void get_suscipious_names(){
        /**# 判断是否有上面列到的敏感名称
         匹配 APK 应用名中出现的 可疑名称
         备注：为避免可疑名称与其他特征冲突, 每个可疑名称后面添加后缀 _name
         :return: 返回出现的可疑名称 的 list**/
        String aName=appName.toLowerCase();
        String sTmp=null;
        for(String sName:suspicious_names){
            if(aName.contains(sName)){
                sTmp=sName+"_name";
                nameList.add(sTmp);
            }
        }
    }

//    public Map<String,Integer> get_suspicious_APIs(){
//        /**
//        匹配 APK 文件中出现的 可疑 API
//        备注：为避免可疑 API与其他特征冲突, 每个可疑 API后面添加后缀 _api
//        :return: 返回出现的可疑 API 的 list
//         */
//        Map<String,Integer> sus_APIs=new HashMap<String, Integer>();
//        String key=null;
//        int c=1;
//        for(String cmd:this.suspicious_APIs){
//            if(z_Strings.contains(String.valueOf(cmd))){
//                key=cmd+"_api";
//                if(sus_APIs.containsKey(key)){
//                    c=sus_APIs.get(key)+1;
//                    sus_APIs.put(key,c);
//                }
//                else {
//                    sus_APIs.put(key,1);
//                }
//            }
//        }
//        return sus_APIs;
//    }


    public List<DexBackedStringReference> getStrings(){
        List<DexBackedStringReference> strings=null;
        System.out.print(String.valueOf(f));
        try {
            DexBackedDexFile dbdf= DexFileFactory.loadDexFile(f,null);
            strings=dbdf.getStrings();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return strings;
    }

//    public Map<String,Integer> get_suspicious_cmds(){
//        Map<String,Integer> sus_cmds=new HashMap<String, Integer>();
//        String key=null;
//        int c=1;
//        for(String cmd:this.suspicious_cmds){
//            if(z_Strings.contains(String.valueOf(cmd))){
//                key=cmd+"_cmd";
//                if(sus_cmds.containsKey(key)){
//                    c=sus_cmds.get(key)+1;
//                    sus_cmds.put(key,c);
//                }
//                else {
//                    sus_cmds.put(key,1);
//                }
//            }
//        }
//        return sus_cmds;
//    }
    String getMD5(){
        try {
            MessageDigest digest = null;
            FileInputStream in = null;
            byte buffer[] = new byte[1024];
            int len;
            digest = MessageDigest.getInstance("MD5");
            in = new FileInputStream(this.apkSourceURI);
            while ((len = in.read(buffer, 0, 1024)) != -1) {
                digest.update(buffer, 0, len);
            }
            in.close();
            BigInteger bigInt = new BigInteger(1, digest.digest());
            return bigInt.toString(16);
        }catch (Exception e){
            return null;
        }
    }

    public void getActivities(){
        ActivityInfo[] activities=null;
        try {
            PackageInfo packageInfo = packageManager.getPackageInfo(this.pkgName, PackageManager.GET_ACTIVITIES );
            activities=packageInfo.activities;

//            for(ActivityInfo a:activities){
//                info = packageManager.getActivityInfo(a.getComponentName(),PackageManager.GET_META_DATA);
//            }

        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        if(activities!=null){
            for(ActivityInfo a:activities){
                if(a!=null){
                    this.activities.add(a.name);

                }
            }
        }
    }


//    public void xmlPr(){
//            int length;
//            ZipFile zipFile;
//            try {
//                zipFile = new ZipFile(apkSourceURI);
//                Enumeration enumeration = zipFile.entries();
//                ZipEntry zipEntry = zipFile.getEntry(("AndroidManifest.xml"));
//                AXmlResourceParser parser = new AXmlResourceParser();
//                parser.open(zipFile.getInputStream(zipEntry));
//                boolean flag = true;
//                while (flag) {
//                    int type = parser.next();
//                    if (type == XmlPullParser.START_TAG) {
//                        int count = parser.getAttributeCount();
//                        for (int i = 0; i < count; i++) {
//                            String name = parser.getAttributeName(i);
//                            String value = parser.getAttributeValue(i);
//                            System.out.println(name+","+value);
//                        }//end for
//                    }
//                    if (type == XmlPullParser.END_DOCUMENT) {
//                        break;
//                    }
//                }// end while
//            } catch (Exception e) {
//
//            }
//    }


//
//        public  void xmlHandle(){
//            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
//            try {
//                ZipFile zipFile = new ZipFile(f);
//                Enumeration enumeration = zipFile.entries();
//                ZipEntry zipEntry = zipFile.getEntry(("AndroidManifest.xml"));
//                FileUtils.copyInputStreamToFile(zipEntry, new File("src/test/resources/AndroidManifest.xml"));
//                // 创建DocumentBuilder对象
//                DocumentBuilder db = dbf.newDocumentBuilder();
//                //加载xml文件
//                Document document = db.parse(zipEntry);
////                NodeList permissionList = document.getElementsByTagName("uses-permission");
////                NodeList activityAll = document.getElementsByTagName("activity");
//                NodeList intent_filter = document.getElementsByTagName("intent-filter");
//                for(int i = 0; i < intent_filter.getLength(); i++){
//                    Node itf = intent_filter.item(i);
//                    String pa=itf.getParentNode().getNodeName();
//                    NamedNodeMap attrs  =itf.getAttributes();
//                    for(int j = 0; j < attrs.getLength(); j++){
//                        String name=attrs.item(j).getNodeName();
//                        if(name == "action"){
//                            String sTem = attrs.item(j).getNodeValue();
//                            activities.add(sTem);
//                        }
//                    }
//                }
//
//                for(int i = 0; i < activityAll.getLength(); i++){
//                    Node activity = activityAll.item(i);
//                    NamedNodeMap attrs  =activity.getAttributes();
//                    for(int j = 0; j < attrs.getLength(); j++){
//                        if(attrs.item(j).getNodeName() == "android:name"){
//                            String sTem = attrs.item(j).getNodeValue();
//                            if(sTem.startsWith(".")){
//                                sTem = pkgName+sTem;
//                            }
//                            activities.add(sTem);
//                        }
//                    }
//                }
//            } catch (ParserConfigurationException e) {
//                // TODO Auto-generated catch block
//                e.printStackTrace();
//            } catch (SAXException e) {
//                // TODO Auto-generated catch block
//                e.printStackTrace();
//            } catch (IOException e) {
//                // TODO Auto-generated catch block
//                e.printStackTrace();
//            }
//        }



    public void getServices(){
        ServiceInfo[] services=null;
        try {
            PackageInfo packageInfo = packageManager.getPackageInfo(this.pkgName, PackageManager.GET_SERVICES );
            services=packageInfo.services;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        if(services!=null){
            for(ServiceInfo s:services){
                if(s!=null){
//                    if(s_services.length()<=1){
//                        s_services="[\""+s.toString()+"\"";
//                    }
//                    else {
//                        s_services=s_services+",\""+s.toString()+"\"";
//                    }
                    this.services.add(s.name);
                }
            }
        }
    }

    public int getProviderNum(){
        ProviderInfo[] p=null;
        try {
            PackageInfo packageInfo = packageManager.getPackageInfo(this.pkgName, PackageManager.GET_PROVIDERS );
            providers=packageInfo.providers;
            if(providers!=null){
                int length=providers.length;
                return length;
            }
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return 0;
    }


    public String getFeature(){
        /** 整合成json形式**/

        Map<String,Object> itemData=new HashMap<>();

        itemData.put("md5",md5);
        itemData.put("activities",activities);
        itemData.put("services",services);
        itemData.put("cmdList",cmdList);
        itemData.put("APIList",APIsList);
        itemData.put("nameList",nameList);
        itemData.put("keywordsListIn",keywordsListIn);
        itemData.put("keywordsListEqual",keywordsListEqual);
        itemData.put("pkgList",pkgList);
        itemData.put("permList",permList);
        itemData.put("urlList",urlList);
        itemData.put("phoneList",phoneList);
        itemData.put("emailList",emailList);
        itemData.put("filesize",fileSize);
        itemData.put("potential_misBhve",potential_misBhve);
        itemData.put("SdkVersion",SdkVersion);
        itemData.put("Day",Day);
        itemData.put("Month",Month);
        itemData.put("Year",Year);
        itemData.put("hasVideo",hasVideo);
        itemData.put("n_activities",n_activities);
        itemData.put("n_intents",n_intents);
        itemData.put("n_providers",n_providers);
        itemData.put("n_services",n_services);
        itemData.put("receiver_priority",receiver_priority
        );
        itemData.put("intents_in_code",intents_in_code);
        itemData.put("hasHTMLDocuments",hasHTMLDocuments);
        itemData.put("hasFakeInstaller3or4Files",hasFakeInstaller3or4Files);
        itemData.put("hasIncognitoAPK",hasIncognitoAPK);
        itemData.put("hasIncognitoDEX",hasIncognitoDEX);
        itemData.put("hasMultiDEX",hasMultiDEX);
        itemData.put("package_name_len",package_name_len);
        itemData.put("package_name_shannon",package_name_shannon);
        itemData.put("is_mismatch_components_and_package",is_mismatch_components_and_package);
        itemData.put("app_name_language",app_name_language);
        itemData.put("so_files",so_files);
        itemData.put("elf_feature",elf_feature);
        itemData.put("potential_misBhve_cnt",potential_misBhve_cnt);

//        String item="{"+s_md5+","+s_activities+","+s_services+","+s_cmdList+","+s_APIList+","+s_nameList+","+s_keywordsListIn+","+s_keywordsListEqual+","+
//                s_pkgList+","+s_permList+","+s_urlList+","+s_phoneList+","+s_emailList+","+s_filesize+","+s_potential_misBhve+","+s_SdkVersion+","+
//                s_Day+","+s_Month+","+s_Year+","+s_hasVideo+","+s_n_activities+","+s_n_intents+","+s_n_providers+","+s_n_services+","+s_receiver_priority+","+
//                s_intents_in_code+","+s_hasHTMLDocuments+","+s_hasFakeInstaller3or4Files+","+s_hasIncognitoAPK+","+s_hasIncognitoDEX+","+s_hasMultiDEX+","+
//                s_package_name_len+","+s_package_name_shannon+","+s_is_mismatch_components_and_package+","+s_app_name_language+","+s_so_files+","+s_elf_feature+","+
//                s_potential_misBhve_cnt+"}";
        JSONObject item=new JSONObject();
        item.putAll(itemData);
        Map<String ,JSONObject> attribute =new HashMap<>();
//        Map<String ,String> attribute =new HashMap<>();
        attribute.put("attribute",item);
        JSONObject jo =new JSONObject();
        jo.putAll(attribute);
        String j_s=jo.toString();
        return j_s;
    }

}
