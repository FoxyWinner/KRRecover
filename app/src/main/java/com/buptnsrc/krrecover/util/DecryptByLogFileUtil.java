package com.buptnsrc.krrecover.util;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Environment;
import android.os.Handler;
import android.util.Log;
import android.view.WindowManager;


import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.buptnsrc.krrecover.activity.ParentActivity;
import com.buptnsrc.krrecover.enums.GlobalEnum;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import android.content.Context;

import static android.os.Looper.getMainLooper;

/**
 * 该方法根据程序运行时log（hook到的）来找到密钥
 */
public class DecryptByLogFileUtil
{
    private static final String TAG = "P-DecryptByLogFileUtil";

    private File rootDir; // 根路径，用来查找log
//    ArrayList<String> whiteList=new ArrayList<>();

    private Map<String, String> pkgNameLogPathMap = new HashMap<>();
    private Map<String, String> appNamePkgNameMap = new HashMap<>();
    private String pkgNameToDecrypt = "";

    public void decryptFiles()
    {
        // 将被加密的日志文件和包名，填充pkgNameAndLogPathMap
        findLogFiles();

        // 判断是否要进入解密流程
        String pkgName = executeDecryptOrNot();

        // 如果pkgName不为空
        if (pkgName != "")
        {
            Log.i("P-DecryptByLogFileUtil", "pkgName is not empty. 启动对pkg的恢复");
            decryptByPkgName(pkgName);
        }
    }

    /**
     * 输入输出流级别的加密解密算法，将inputFile解密存入outputFile
     *
     * @param inputFileName
     * @param outputFileName
     * @param transforma
     * @param decodedKey
     * @param algorithm
     * @param Iv
     * @throws Exception
     */
    public void decrypt(String inputFileName, String outputFileName, String transforma, byte[] decodedKey, String algorithm, byte[] Iv) throws Exception
    {

        byte[] key_decoded = new byte[decodedKey.length];
        for (int x = 0; x < decodedKey.length; x++)
        {
            key_decoded[x] = decodedKey[x];
        }
        byte[] iv = new byte[Iv.length];
        for (int y = 0; y < Iv.length; y++)
        {
            iv[y] = Iv[y];
        }
        // java.lang.IllegalArgumentException
        final Cipher cipher = Cipher.getInstance(transforma);
        final SecretKeySpec key = new SecretKeySpec(key_decoded, algorithm);
        AlgorithmParameterSpec spec = new IvParameterSpec(iv);

        FileInputStream fileInputStream = new FileInputStream(inputFileName);
        FileOutputStream fileOutputStream = new FileOutputStream(outputFileName);

        cipher.init(2, key, spec);
        CipherInputStream v1 = new CipherInputStream(((InputStream) fileInputStream), cipher);
        byte[] bytes = new byte[8];
        while (true)
        {
            int v0 = v1.read(bytes);
            if (v0 == -1)
            {
                break;
            }
            fileOutputStream.write(bytes, 0, v0);
        }
        fileOutputStream.flush();
        fileOutputStream.close();
        v1.close();
    }

    /**
     * 解锁该pkgName加密的各文件
     *
     * @param pkgName
     */
    public void decryptByPkgName(String pkgName)
    {
        String logFile = pkgNameLogPathMap.get(pkgName);
        Set<String> filesToDecrypt = new HashSet<>();
        String transforma = null;

        JSONObject jsonObject;
        String hookedClassName;
        String hookedMethodName;

        JSONArray args;
        byte[] decodedKey = new byte[0];
        String algorithm = null;
        byte[] iv = new byte[0];

        try
        {
            InputStream inputStream = new FileInputStream(logFile);
            if (inputStream != null)
            {
                // 从log文件中获取密钥以及待解密的文件列表
                InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                String oneLineStr = bufferedReader.readLine();
                // 分行读取
                while (oneLineStr != null && oneLineStr.length() > 0)
                {
                    jsonObject = JSON.parseObject(oneLineStr);
                    hookedClassName = jsonObject.getString("class");
                    hookedMethodName = jsonObject.getString("method");
                    args = jsonObject.getJSONArray("args");
                    if (hookedClassName.equals("javax.crypto.Cipher") && hookedMethodName.equals("getInstance"))
                    {
                        Log.i("P-DecryptByLogFileUtil", "transforma：" + transforma);
                        transforma = (String) args.get(0);
                    } else if (hookedClassName.equals("javax.crypto.Cipher") && hookedMethodName.equals("init"))
                    {
                        JSONObject keyJSONObject = (JSONObject) args.get(1);
                        JSONArray jsonArray = (JSONArray) keyJSONObject.get("key");
                        byte[] tmp = new byte[jsonArray.size()];
                        for (int i = 0; i < jsonArray.size(); i++)
                        {
                            tmp[i] = jsonArray.getByteValue(i);
                        }

                        decodedKey = tmp;
                        algorithm = keyJSONObject.getString("algorithm");
                        jsonArray = ((JSONArray) (((JSONObject) args.get(2)).get("iv")));
                        byte[] t = new byte[jsonArray.size()];

                        for (int i = 0; i < jsonArray.size(); i++)
                        {
                            t[i] = jsonArray.getByteValue(i);
                        }
                        iv = t;
                    }
                    // 这个分支虽然在代码中未删去，实际上它并不会产生效果。因为不明原因hook不到FileOutputStream
                    else if (hookedClassName.equals("java.io.FileOutputStream") && hookedMethodName.equals("java.io.FileOutputStream"))
                    {
                        if (args.size() == 1)
                        {
                            try
                            {
                                String fileName = (String) args.get(0);
                                filesToDecrypt.add(fileName.trim());
                            } catch (Exception e)
                            {
                                // 避免情况："args":[{"path":"\/data\/data\/com.simplelocker\/shared_prefs\/AppPrefs.xml"}]。该情况不用作处理
                            }
                        }
                    }
                    // 20201217 我们想到的第一个方法是直接hook java.io.File，看第一个arg的末尾名是否为.enc，简单直接
                    else if (hookedClassName.equals("java.io.File") && hookedMethodName.equals("java.io.File"))
                    {
                        if (args.size() == 1)
                        {
                            try
                            {
                                String fileName = (String) args.get(0);
                                if (fileName.endsWith(".enc"))
                                {
                                    filesToDecrypt.add(fileName.trim());
                                    Log.i(TAG, "fileName:" + fileName);
                                }
                            } catch (Exception e)
                            {
                                e.printStackTrace();
                                Log.e("P-DecryptByLogFileUtil", "hook加密文件名错误");
                            }
                        }
                    }
                    // 202012171223 我们发现class为IoBridge、第二个arg为"577"的hook的信息，第一个参数即为被加密文件。这是fileOutStream调用的更深层的c核心方法，比fileOutStream得到的信息更靠谱
                    else if (hookedClassName.equals("libcore.io.IoBridge") && hookedMethodName.equals("open"))
                    {
                        String fileName = (String) args.get(0);
                        String num = (String) args.get(1);

                        // 两参数函数，第二参数为577，且第一参数不含包名（排除勒索软件对自身data，一般是xml文件，做的写操作）
                        if (args.size() == 2 && num.equals("577") && !fileName.contains(pkgName))
                        {
                            try
                            {
                                filesToDecrypt.add(fileName.trim());
                                Log.i(TAG, "fileName:" + fileName);
                            } catch (Exception e)
                            {
                                e.printStackTrace();
                                Log.e("P-DecryptByLogFileUtil", "hook加密文件名错误");
                            }
                        }
                    }

                    oneLineStr = bufferedReader.readLine();
                }
                inputStream.close();

                // 试一下直接解密  ->  解密是正常的，关键无法正确hook到被加密文件的路径
//                filesToDecrypt.add("/storage/sdcard/test.txt.enc");

                Log.i("P-DecryptByLogFileUtil", "跳出循环，如果以下长度均>0，则进入解密流程");
                Log.i("P-DecryptByLogFileUtil", "transforma.length()：" + transforma.length());
                Log.i("P-DecryptByLogFileUtil", "decodedKey.length：" + decodedKey.length);
                Log.i("P-DecryptByLogFileUtil", "algorithm.length()：" + algorithm.length());
                Log.i("P-DecryptByLogFileUtil", "iv.length：" + iv.length);
                Log.i("P-DecryptByLogFileUtil", "filesToDecrypt.size()：" + filesToDecrypt.size());

                // 对每个文件进行解密操作
                if (transforma.length() > 0 && decodedKey.length > 0 && algorithm.length() > 0 && iv.length > 0 && filesToDecrypt.size() > 0)
                {
                    Log.i("P-DecryptByLogFileUtil", "进入真正的解密操作");


                    for (String fileName : filesToDecrypt)
                    {
                        try
                        {
                            // 例：若filename为A.doc.enc，则解密后的文件名为A.doc
                            String outputFileName = fileName.substring(0, fileName.lastIndexOf("."));
                            if (outputFileName.lastIndexOf(".") > 0)
                            {
                                Log.i("P-DecryptByLogFileUtil", "解密中fileName: " + fileName);
                                Log.i("P-DecryptByLogFileUtil", "解密后的outputFileName将是: " + outputFileName);


                                decrypt(fileName, outputFileName, transforma, decodedKey, algorithm, iv);

                                // 删除解密前文件
                                File fileBeforeDecrypt = new File(fileName);
                                if (fileBeforeDecrypt.exists())
                                {
                                    Log.i("P-DecryptByLogFileUtil", "删除解密前文件" + fileName);
                                    fileBeforeDecrypt.delete();
                                }
                            } else
                            {
                                outputFileName = outputFileName + "__tmp";
                                Log.i("P-DecryptByLogFileUtil", "fileName：" + fileName);
                                Log.i("P-DecryptByLogFileUtil", "outputFileName：" + outputFileName);
                                decrypt(fileName, outputFileName, transforma, decodedKey, algorithm, iv);

                                // 删除解密前文件，重命名解密后文件
                                File fileBeforeDecrypt = new File(fileName);
                                if (fileBeforeDecrypt.exists())
                                {
                                    fileBeforeDecrypt.delete();
                                }

                                new File(outputFileName).renameTo(fileBeforeDecrypt);
                            }
                        } catch (Exception e)
                        {

                        }

                    }
                }
            }
        } catch (FileNotFoundException e)
        {
            e.printStackTrace();
        } catch (IOException e)
        {
            e.printStackTrace();
        } catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    /**
     * 根据pkgNameAndLogPathMap中符合条件的app个数，判断是否执行解密行为。如果pkgName返回不为空，那说明需要解密
     *
     * @return
     */
    public String executeDecryptOrNot()
    {
        // size为0返回空字符串
        if (pkgNameLogPathMap.size() == 0)
        {
            Log.i("P-DecryptByLogFileUtil", "pkgNameLogPathMap is empty. 没有找到任何可用日志");
            return "";
        }
        // size为1返回这唯一pkgName
        else if (pkgNameLogPathMap.size() == 1)
        {
            Log.i("P-DecryptByLogFileUtil", "pkgNameLogPathMap is one. 恢复该pkg对应内容");
            for (String pkgName : pkgNameLogPathMap.keySet())
            {
                return pkgName;
            }
        } else
        {// 多选一
//        app_logFiles.put("com.example.mac.packantiransom","文件1");
//        app_logFiles.put("com.buptnsrc.packantiransomchild.service","文件2");
            Log.i("P-DecryptByLogFileUtil", "pkgNameLogPathMap is " + pkgNameLogPathMap.size() + ". 选择以进行恢复");

            String[] mapKeys = pkgNameLogPathMap.keySet().toArray(new String[0]);

            PackageManager packageManager = ParentActivity.context.getPackageManager();
            for (String pkgName : mapKeys)
            {
                try
                {
                    // 找到对应pkgName所对应的applicationInfo，从而找到appName和pkgName的对应关系，放入map
                    ApplicationInfo applicationInfo = packageManager.getApplicationInfo(pkgName, PackageManager.GET_META_DATA);
                    String appName = packageManager.getApplicationLabel(applicationInfo).toString();
                    appNamePkgNameMap.put(appName, pkgName);
                } catch (PackageManager.NameNotFoundException e)
                {
                    e.printStackTrace();
                }
            }
            final String[] appName = appNamePkgNameMap.keySet().toArray(new String[0]);

            // 传入appName数组，通过弹窗选出一个，返回appName
            return chooseOneApp(appName);
        }

        return "";
    }

    /**
     * 弹出对话框，让用户选择待解锁的appNames
     *
     * @param appNames
     * @return 选择的appName对应的pkgName
     */
    public String chooseOneApp(final String[] appNames)
    {
        // 从主线程中创建handler，handleMessage运行于主线程中，因为隶属于主线程，该handler可以更改UI
        Handler mHandler = new Handler(getMainLooper());
        mHandler.post(new Runnable()
        {
            @Override
            public void run()
            {
                AlertDialog chooseDialog;
//            final String[] items = {"单选1", "单选2", "单选3", "单选4"};
                AlertDialog.Builder alertBuilder = new AlertDialog.Builder(ParentActivity.context);
                alertBuilder.setTitle("请选择想要解锁的App");
                alertBuilder.setSingleChoiceItems(appNames, 0, new DialogInterface.OnClickListener()
                {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i)
                    {
                        pkgNameToDecrypt = String.valueOf(appNamePkgNameMap.get(appNames[i]));
                    }
                });
                alertBuilder.setPositiveButton("确定", new DialogInterface.OnClickListener()
                {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i)
                    {
                        Log.i("P-DecryptByLogFileUtil】", "pkgNameToDecrypt" + pkgNameToDecrypt);
                    }
                });
                alertBuilder.setNegativeButton("取消", new DialogInterface.OnClickListener()
                {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i)
                    {
                        pkgNameToDecrypt = "";
                        Log.i("P-DecryptByLogFileUtil", "Cancel pkgNameToDecrypt" + pkgNameToDecrypt);
                    }
                });
                chooseDialog = alertBuilder.create();
                chooseDialog.getWindow().setType(WindowManager.LayoutParams.TYPE_TOAST);
                chooseDialog.show();
            }
        });
        return pkgNameToDecrypt;
    }

//    // tmpWhiteList 暂时的白名单，等待从子apk那边分享得到
//    public void tmpWhiteList(){
//        whiteList.add("com.example.mac.packantiransom");
//        whiteList.add("com.buptnsrc.packantiransomchild.service");
//    }


    /**
     * 在目录中递归查找日志文件，后来证实无需递归，因为sandbox打印出的log就在根目录下
     *
     * @param rootDir
     * @param whiteListSharedPreferences
     */
    private void detectLogFilesInDir(File rootDir, SharedPreferences whiteListSharedPreferences)
    {
        File files[] = rootDir.listFiles();
        if (files != null)
        {
            for (File file : files)
            {
                if (file.isDirectory())
                {
                    detectLogFilesInDir(file, whiteListSharedPreferences);
                } else
                {
                    String fileName = file.getName();

                    if (fileName.endsWith(".log") && fileName.startsWith(GlobalEnum.SANDBOX_LOG_PREFIX.getString()))
                    {
                        Log.i("P-DecryptByLogFileUtil", "日志文件找到， fileName：" + fileName);
                        // 沙盒log前缀刚好11位，提取log文件所对应软件的packageName
                        String pkgName = fileName.substring(11, fileName.length() - 4);
                        // 若packageName不在白名单内，则对该log文件进行分析。否则不分析
                        if (!whiteListSharedPreferences.contains(pkgName))
                        {
                            File logFile = new File(rootDir, fileName);
                            Boolean filesAreEncrypted = filesAreEncrypted(logFile);
                            if (filesAreEncrypted)
                            {
                                Log.i("P-DecryptByLogFileUtil", "文件确认被加密， pkgName：" + pkgName + "，fileName：" + logFile.getAbsolutePath());
                                pkgNameLogPathMap.put(pkgName, logFile.getAbsolutePath());
                            }
                        }
                    }
                }
            }
        }
    }


    /**
     * findLogFiles 遍历目录下符合条件的log文件，并将被锁的packageName与log文件路径一同存放在pkgNameAndLogPathMap键值对中
     */
    public void findLogFiles()
    {
        Log.i("P-DecryptByLogFileUtil", "查找日志");

        rootDir = new File(Environment.getExternalStorageDirectory().toString());

        SharedPreferences whiteListSharedPreferences = ParentActivity.context.getSharedPreferences(GlobalEnum.WHITE_LIST.getString(), Context.MODE_WORLD_READABLE + Context.MODE_WORLD_WRITEABLE + Context.MODE_MULTI_PROCESS);

        // todo 思路不太对，为什么遍历rootDir？根本找不到log文件

        // 我改为了递归遍历
        detectLogFilesInDir(rootDir, whiteListSharedPreferences);
//        if(rootFileList.length > 0)
//        {
//            // 遍历文件列表，找出文件拓展名为.log或者沙盒导出的log：startsWith"sandboxLog_"
//            for(int i = 0; i < rootFileList.length; ++i)
//            {
//                String fileName = rootFileList[i].getName();
//                Log.i("P-DecryptByLogFileUtil", fileName);
//
//                if(fileName.endsWith(".log") && fileName.startsWith(GlobalEnum.SANDBOX_LOG_PREFIX.getString()))
//                {
//                    Log.i("P-DecryptByLogFileUtil", "日志文件找到， fileName：" + fileName);
//                    // 沙盒log前缀刚好11位，提取log文件所对应软件的packageName
//                    pkgName = fileName.substring(11 , fileName.length() - 4);
//                    // 若packageName不在白名单内，则对该log文件进行分析。否则不分析
//                    if(!whiteListSharedPreferences.contains(pkgName))
//                    {
//                        File logFile = new File(rootDir, fileName);
//                        filesAreEncrypted = filesAreEncrypted(logFile);
//                        if(filesAreEncrypted)
//                        {
//                            pkgNameLogPathMap.put(pkgName,logFile.getAbsolutePath());
//                        }
//                    }
//                }
//            }
//        }
    }

    /**
     * isEncryptLogFile判断log文件内是否同时包含三条被hook的关键信息：cipher.init(1,key,iv)，cipher.getinstance(t),fileoutputstream(f)
     *
     * @param logFile 日志文件
     * @return
     */
    public boolean filesAreEncrypted(File logFile)
    {
        // 当三个条件同时满足，我们判断文件被加密了
        boolean usedCipherGetinstanceMethod = false;
        boolean usedCipherInitMethod = false;
        boolean usedFileOutputStream = false;

        // 打开文件输入流
        try
        {
            InputStream inputStream = new FileInputStream(logFile);
            if (inputStream != null)
            {
                InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                String oneLineStr;
                //分行读取
                while ((oneLineStr = bufferedReader.readLine()) != null)
                {
                    JSONObject jsonObject = JSON.parseObject(oneLineStr);
                    String hookedClassName = jsonObject.getString("class");
                    String hookedMethodName = jsonObject.getString("method");
                    if (hookedClassName.equals("javax.crypto.Cipher") && hookedMethodName.equals("getInstance"))
                    {
                        usedCipherGetinstanceMethod = true;
                    } else if (hookedClassName.equals("javax.crypto.Cipher") && hookedMethodName.equals("init"))
                    {
                        String encryptOrDecrypt = String.valueOf(jsonObject.getJSONArray("args").get(0));
                        if (encryptOrDecrypt.equals("1"))
                        {
                            usedCipherInitMethod = true;
                        }
                    } else if (hookedClassName.equals("java.io.FileOutputStream") && hookedMethodName.equals("java.io.FileOutputStream"))
                    {
                        // todo 我们暂时不看这个usedFileOutputStream的值了，因为hook不到这个方法不知道为什么
//                            usedFileOutputStream = true;
                    }
                }
                inputStreamReader.close();
                inputStream.close();
            }
        } catch (FileNotFoundException e)
        {
            e.printStackTrace();
        } catch (IOException e)
        {
            e.printStackTrace();
        }

        Log.i("P-DecryptByLogFileUtil", "最终：usedCipherGetinstanceMethod:" + usedCipherGetinstanceMethod + "，usedCipherInitMethod：" + usedCipherInitMethod + "，usedFileOutputStream：" + usedFileOutputStream);

        // todo 我们暂时不看这个usedFileOutputStream的值了，因为hook不到这个方法不知道为什么
//        boolean isEncrypted = usedCipherGetinstanceMethod && usedCipherInitMethod && usedFileOutputStream;
        boolean isEncrypted = usedCipherGetinstanceMethod && usedCipherInitMethod;

        return isEncrypted;
    }


    /**
     * 该方法用于测试阶段测试copyfile方法的有效性
     */
    public void testHookOutPutStream()
    {
        //要复制的 源文件
        File file = new File("/storage/sdcard/test.txt.enc");

        File copyFile = new File("/storage/sdcard/test.txt.enccy");
        try
        {
            //执行copy方法；
            copyfile(file, copyFile);
        } catch (Exception e)
        {
            e.printStackTrace();
        }
    }


    public void copyfile(File src, File target) throws Exception
    {
        //创建一个文件输入流
        FileInputStream input = new FileInputStream(src);
        //创建一个文件输出流
        FileOutputStream out = new FileOutputStream(target);
        //方法一str
        //定义一个变量接受读取到的字节
/*        int b = -1;
        while ((b=input.read())!=-1){
            //System.err.println((char) b); // 把b接受的字符转成char 其实打印的就是计算机编码
            //把读到的字节写入到目标文件
            out.write(b);
        }*/
        //方法一end 方法二str 如果文件较大也可以设置缓冲区 如下；
        /*
         *下面是设置了缓存区 相比上边方法效率要高很多
         * 相比上边的方法有点像喝水 每次一滴一滴喝 不太过瘾 加缓存区好比是那杯子接满了 一下喝完 杯子就是我们下边声明的数组；
         *
         **/
        //定义一个用来缓冲的数组  就是每次读到的字节先放到缓存区然后一并输出提高效率；
        byte[] b = new byte[1024];
        //用来接收每次读到的字节数量；
        int len = -1;
        //read(byte[]) 读取一定数量的字节也就是参数设置的大小 放到缓存区 返回每次读取的字节数量   read() 返回每次读取到的字节；
        while ((len = input.read(b)) != -1)
        {
            //将缓存区的字节输出到目标文件 因为文件末尾读到的字节数不确定所以 每次输出缓存区的 0 到 实际读到的字节长度；
            out.write(b, 0, len);
        }
        //因为输入出流用到系统级资源 所以要关流释放资源；
        input.close();
        out.close();
    }
}
