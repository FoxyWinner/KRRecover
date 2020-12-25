//package com.buptnsrc.packantiransom.activity;
//
//
//import android.app.AlertDialog;
//import android.content.Context;
//import android.content.DialogInterface;
//import android.content.Intent;
//import android.os.Bundle;
//import android.os.Handler;
//import android.os.Message;
//import android.os.Parcelable;
//import android.os.PersistableBundle;
//import android.support.annotation.Nullable;
//import android.support.v7.app.AppCompatActivity;
//import android.util.Log;
//import android.view.WindowManager;
//
//import com.buptnsrc.packantiransom.activity.MainActivity;
//import com.example.mac.packantiransom.R;
//import com.buptnsrc.packantiransom.modelDetect.AnalysisService;
//
//public class alertWindow extends AppCompatActivity {
//    public static Context context;
//    MainHandler mainHandler;
//    public alertWindow(){
//        super();
//    }
//
//    class MainHandler extends Handler {
//        @Override
//        public void handleMessage(Message msg) {
//            switch (msg.what) {
//                case 1:
//                    Intent v4_1 = new Intent(context, AnalysisService.class);
//                    v4_1.putExtra("APPINFO", (Parcelable)msg.obj);
//                    startService(v4_1);
//                    break;
//            }
//        }
//    }
//    @Override
//    public void onCreate(Bundle arg2) {
//        super.onCreate(arg2);
//        setContentView(R.layout.activity_window);
//        context=this;
//        Log.i("alertWindow","onCreate");
////        start();
//        Log.i("alertWindow","start");
//        mainHandler = new MainHandler();
//        Intent intent=getIntent();
//        final Parcelable appInfor=intent.getParcelableExtra("APPINFO");
//        new Thread(new Runnable() {
//            @Override
//            public void run() {
//                Message msg3 = Message.obtain();
//                msg3.what = 1; // 消息标识
//                msg3.obj = appInfor; // 消息内存存放
//                mainHandler.sendMessage(msg3);
//            }
//        }).start();
//
//    }
//
//    public void start(){
//
//    }
//
//    public static void window(final String appName){
//
//
//                Log.i("here~","startAlertWindow");
//                String message= "新安装应用<"+appName+">疑似勒索软件！您可选择手动将其加入以下名单。若您选择白名单，您将失去我们提供的守护。";
//                android.app.AlertDialog.Builder builder = new AlertDialog.Builder(context);//只有activity才能使用window
//                builder.setTitle("警告！");
//                builder.setMessage(message);
////        builder.setIcon(R.mipmap.ic_launcher);
//                builder.setPositiveButton("可疑名单", new DialogInterface.OnClickListener() {//添加"Yes"按钮
//                    @Override
//                    public void onClick(DialogInterface dialogInterface, int i) {
//                        // 先啥也不干
//                    }
//                });
//                builder.setNegativeButton("白名单", new DialogInterface.OnClickListener() {//添加取消
//                    @Override
//                    public void onClick(DialogInterface dialogInterface, int i) {
//                        // 先啥也不干
//                    }
//                });
//                builder.setNeutralButton("默认", new DialogInterface.OnClickListener() {//添加普通按钮
//                    @Override
//                    public void onClick(DialogInterface dialogInterface, int i) {
//                        // 先啥也不干
//                    }
//                });
////                builder.show();
//                AlertDialog dialog =builder.create();
//                dialog.getWindow().setType(WindowManager.LayoutParams.TYPE_TOAST);
//                dialog.show();
//
//
//    }
//
//    @Override
//    protected void onDestroy() {
//        super.onDestroy();
//    }
//}
