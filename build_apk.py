"""
build_apk.py — Compilador automatizado de APK para Android (Mobile y Tablet)
JEV // SOC L2 Cyber Command OS (LangChain LCEL Edition)
Ensambla, dexifica, alinea y firma el APK oficial utilizando Android SDK Build-Tools.
"""

import os
import shutil
import subprocess
import zipfile
from pathlib import Path


def main():
    root_dir = Path(__file__).resolve().parent
    android_sdk = Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk"
    build_tools = android_sdk / "build-tools" / "35.0.0"
    android_jar = android_sdk / "platforms" / "android-34" / "android.jar"

    aapt2 = build_tools / "aapt2.exe"
    d8 = build_tools / "d8.bat"
    zipalign = build_tools / "zipalign.exe"
    apksigner = build_tools / "apksigner.bat"

    work_dir = root_dir / "build_apk_tmp"
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True)

    res_compiled = work_dir / "compiled_res"
    res_compiled.mkdir(parents=True)
    gen_src = work_dir / "gen"
    gen_src.mkdir(parents=True)
    classes_dir = work_dir / "classes"
    classes_dir.mkdir(parents=True)

    print("[1/7] Preparando recursos y assets para Mobile & Tablet...")
    # Asegurar que index.html y PDF estén al día
    assets_dir = work_dir / "assets"
    assets_dir.mkdir(parents=True)
    shutil.copy2(root_dir / "index.html", assets_dir / "index.html")
    shutil.copy2(root_dir / "Informe_Final_SOC_L2_Incidentes.pdf", assets_dir / "Informe_Final_SOC_L2_Incidentes.pdf")
    if (root_dir / "soc_l2_dashboard_summary.png").exists():
        shutil.copy2(root_dir / "soc_l2_dashboard_summary.png", assets_dir / "soc_l2_dashboard_summary.png")

    # Recursos mínimos (values, drawable)
    res_dir = work_dir / "res"
    values_dir = res_dir / "values"
    drawable_dir = res_dir / "drawable"
    values_dir.mkdir(parents=True)
    drawable_dir.mkdir(parents=True)

    (values_dir / "strings.xml").write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">JEV SOC L2 Command</string>
</resources>
""",
        encoding="utf-8",
    )

    (drawable_dir / "ic_launcher.xml").write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
    <path android:fillColor="#040711" android:pathData="M0,0h108v108h-108z"/>
    <path android:fillColor="#00F0FF" android:pathData="M54,22L28,33v20c0,16.5 11.1,31.8 26,36c14.9,-4.2 26,-19.5 26,-36V33L54,22z"/>
    <path android:fillColor="#FF2A5F" android:pathData="M56,36L42,56h10l-2,16l16,-20H56L56,36z"/>
</vector>
""",
        encoding="utf-8",
    )

    manifest_path = work_dir / "AndroidManifest.xml"
    manifest_path.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.jev.socl2.command"
    android:versionCode="3"
    android:versionName="3.0-LCEL-MobileTablet">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

    <supports-screens
        android:smallScreens="true"
        android:normalScreens="true"
        android:largeScreens="true"
        android:xlargeScreens="true"
        android:anyDensity="true" />

    <application
        android:label="@string/app_name"
        android:icon="@drawable/ic_launcher"
        android:hardwareAccelerated="true"
        android:resizeableActivity="true"
        android:usesCleartextTraffic="true">

        <activity
            android:name="com.jev.socl2.command.MainActivity"
            android:exported="true"
            android:configChanges="orientation|screenSize|screenLayout|smallestScreenSize|keyboardHidden|uiMode"
            android:windowSoftInputMode="adjustResize">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
        encoding="utf-8",
    )

    print("[2/7] Compilando recursos con aapt2...")
    # Compilar drawables y values
    subprocess.run(
        [str(aapt2), "compile", "--dir", str(res_dir), "-o", str(res_compiled / "resources.zip")],
        check=True,
    )

    unaligned_apk = work_dir / "unaligned.apk"
    print("[3/7] Enlazando APK y generando R.java con aapt2 link...")
    subprocess.run(
        [
            str(aapt2),
            "link",
            "-o",
            str(unaligned_apk),
            "-I",
            str(android_jar),
            "--manifest",
            str(manifest_path),
            "-A",
            str(assets_dir),
            "--java",
            str(gen_src),
            "--auto-add-overlay",
            str(res_compiled / "resources.zip"),
        ],
        check=True,
    )

    print("[4/7] Escribiendo código nativo Android en Java...")
    pkg_dir = gen_src / "com" / "jev" / "socl2" / "command"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    java_src = pkg_dir / "MainActivity.java"
    java_src.write_text(
        """package com.jev.socl2.command;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.res.AssetManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class MainActivity extends Activity {

    private WebView webView;
    private ValueCallback<Uri[]> uploadMessage;
    private final static int FILECHOOSER_RESULTCODE = 1001;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Estilo de barra de estado oscura acorde a la paleta JEV Cyber Command (#040711)
        Window window = getWindow();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            window.setStatusBarColor(Color.parseColor("#040711"));
            window.setNavigationBarColor(Color.parseColor("#040711"));
        }

        webView = new WebView(this);
        webView.setBackgroundColor(Color.parseColor("#040711"));
        setContentView(webView);

        configureWebView();
        webView.loadUrl("file:///android_asset/index.html");
    }

    private void configureWebView() {
        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(true);
        s.setAllowContentAccess(true);
        s.setUseWideViewPort(true);
        s.setLoadWithOverviewMode(true);
        s.setBuiltInZoomControls(true);
        s.setDisplayZoomControls(false);
        s.setDatabaseEnabled(true);
        s.setCacheMode(WebSettings.LOAD_DEFAULT);

        webView.addJavascriptInterface(new JevBridge(this), "JevAndroidBridge");

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                if (request != null && request.getUrl() != null) {
                    String url = request.getUrl().toString();
                    if (url.startsWith("http://") || url.startsWith("https://")) {
                        try {
                            Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
                            startActivity(browserIntent);
                            return true;
                        } catch (Exception ignored) {}
                    }
                }
                return false;
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                if (url != null && (url.startsWith("http://") || url.startsWith("https://"))) {
                    try {
                        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
                        startActivity(browserIntent);
                        return true;
                    } catch (Exception ignored) {}
                }
                return false;
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> filePathCallback, FileChooserParams fileChooserParams) {
                if (uploadMessage != null) {
                    uploadMessage.onReceiveValue(null);
                    uploadMessage = null;
                }
                uploadMessage = filePathCallback;

                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("*/*");
                try {
                    startActivityForResult(Intent.createChooser(intent, "Seleccionar archivo Excel SIEM (.xlsx)"), FILECHOOSER_RESULTCODE);
                    return true;
                } catch (Exception e) {
                    uploadMessage = null;
                    return false;
                }
            }
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent intent) {
        super.onActivityResult(requestCode, resultCode, intent);
        if (requestCode == FILECHOOSER_RESULTCODE) {
            if (uploadMessage == null) return;
            Uri[] results = null;
            if (resultCode == Activity.RESULT_OK && intent != null) {
                String dataString = intent.getDataString();
                ClipData clipData = intent.getClipData();
                if (clipData != null) {
                    results = new Uri[clipData.getItemCount()];
                    for (int i = 0; i < clipData.getItemCount(); i++) {
                        results[i] = clipData.getItemAt(i).getUri();
                    }
                } else if (dataString != null) {
                    results = new Uri[]{Uri.parse(dataString)};
                }
            }
            uploadMessage.onReceiveValue(results);
            uploadMessage = null;
        }
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    public class JevBridge {
        private final Context context;

        public JevBridge(Context context) {
            this.context = context;
        }

        @JavascriptInterface
        public void copyToClipboard(final String text, final String label) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    ClipboardManager clipboard = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
                    ClipData clip = ClipData.newPlainText(label, text);
                    if (clipboard != null) {
                        clipboard.setPrimaryClip(clip);
                        Toast.makeText(context, "✓ " + label + " copiado", Toast.LENGTH_SHORT).show();
                    }
                }
            });
        }

        @JavascriptInterface
        public void shareTextFile(final String filename, final String content) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Intent shareIntent = new Intent(Intent.ACTION_SEND);
                        shareIntent.setType("text/plain");
                        shareIntent.putExtra(Intent.EXTRA_SUBJECT, "Regla de Detección SOC L2: " + filename);
                        shareIntent.putExtra(Intent.EXTRA_TEXT, content);
                        context.startActivity(Intent.createChooser(shareIntent, "Compartir " + filename));
                    } catch (Exception e) {
                        Toast.makeText(context, "Error: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                }
            });
        }

        @JavascriptInterface
        public void openNativePdfViewer() {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    try {
                        File outFile = new File(context.getExternalFilesDir(null), "Informe_Final_SOC_L2_Incidentes.pdf");
                        AssetManager am = context.getAssets();
                        try (InputStream in = am.open("Informe_Final_SOC_L2_Incidentes.pdf");
                             OutputStream out = new FileOutputStream(outFile)) {
                            byte[] buffer = new byte[8192];
                            int read;
                            while ((read = in.read(buffer)) != -1) {
                                out.write(buffer, 0, read);
                            }
                        }
                        Intent pdfIntent = new Intent(Intent.ACTION_VIEW);
                        pdfIntent.setDataAndType(Uri.fromFile(outFile), "application/pdf");
                        pdfIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                        context.startActivity(Intent.createChooser(pdfIntent, "Abrir Informe Oficial SOC Nivel 2"));
                    } catch (Exception e) {
                        Toast.makeText(context, "Abriendo descarga: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                }
            });
        }
    }
}
""",
        encoding="utf-8",
    )

    print("[5/7] Compilando clases Java con javac y dexificando con d8...")
    java_files = list(gen_src.rglob("*.java"))
    subprocess.run(
        [
            "javac",
            "--release",
            "8",
            "-cp",
            str(android_jar),
            "-d",
            str(classes_dir),
        ]
        + [str(f) for f in java_files],
        check=True,
    )

    class_files = list(classes_dir.rglob("*.class"))
    subprocess.run(
        [
            str(d8),
            "--lib",
            str(android_jar),
            "--min-api",
            "26",
            "--output",
            str(work_dir),
        ]
        + [str(f) for f in class_files],
        check=True,
        shell=True,
    )

    print("[6/7] Incorporando classes.dex y alineando con zipalign...")
    with zipfile.ZipFile(unaligned_apk, "a", compression=zipfile.ZIP_DEFLATED) as apk_zip:
        apk_zip.write(work_dir / "classes.dex", "classes.dex")

    aligned_apk = work_dir / "aligned.apk"
    subprocess.run(
        [str(zipalign), "-f", "-v", "4", str(unaligned_apk), str(aligned_apk)],
        check=True,
    )

    print("[7/7] Firmando APK con apksigner...")
    keystore_path = work_dir / "debug.keystore"
    subprocess.run(
        [
            "keytool",
            "-genkeypair",
            "-v",
            "-keystore",
            str(keystore_path),
            "-storepass",
            "android",
            "-alias",
            "androiddebugkey",
            "-keypass",
            "android",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
            "-dname",
            "CN=JEV SOC L2, OU=CyberCommand, O=DojoCommunity, L=Lima, ST=Lima, C=PE",
        ],
        check=True,
    )

    final_apk = root_dir / "JEV_SOC_L2_Cyber_Command_Mobile_Tablet.apk"
    subprocess.run(
        [
            str(apksigner),
            "sign",
            "--ks",
            str(keystore_path),
            "--ks-pass",
            "pass:android",
            "--ks-key-alias",
            "androiddebugkey",
            "--key-pass",
            "pass:android",
            "--out",
            str(final_apk),
            str(aligned_apk),
        ],
        check=True,
        shell=True,
    )

    # Verificar firma del APK
    subprocess.run([str(apksigner), "verify", "--verbose", str(final_apk)], check=True, shell=True)

    apk_size = final_apk.stat().st_size
    print(f"\n✨ ¡ÉXITO ROTUNDO! APK compilado y firmado: {final_apk.name} ({apk_size:,} bytes)")
    print(f"   Ubicación: {final_apk}")


if __name__ == "__main__":
    main()
