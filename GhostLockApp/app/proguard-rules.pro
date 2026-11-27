# HonorRoot R8 规则
#
# 目的：debug 构建也走 R8，把 dex 从 ~40 MB 压到 ~15 MB。
# 交付物一直是 debug 签名（apksigner v2 有效），R8 不影响签名方式。
#
# 必须保留的东西：
#  1. Shizuku API —— rikka.shizuku 通过反射取 binder 与 newProcess，
#     混淆类名/方法名会让 Shizuku.newProcess 在运行期找不到。
#  2. Kotlin Metadata —— Compose 编译器与 kotlinx-serialization 依赖它。
#  3. enum valueOf/values —— EngineCatalog、ManagerCatalog 等用 enumEntries()，
#     混淆 enum 名字会让反射拿不到常量名。
#  4. 自定义 View / Activity —— 系统按类名反射实例化（AndroidManifest 里写了名字）。

# ---- Shizuku ----
-keep class rikka.shizuku.** { *; }
-keep class moe.shizuku.** { *; }
-keep class rikka.shizuku.ShizukuProvider { *; }
-dontwarn rikka.shizuku.**

# ---- Kotlin ----
-keepattributes *Annotation*, InnerClasses, Signature, EnclosingMethod
-keepattributes RuntimeVisibleAnnotations, AnnotationDefault
-dontwarn kotlin.**
-keepclassmembers class **$WhenMappings { <fields>; }
-keep class kotlin.Metadata { *; }
-keep class kotlin.enums.EnumEntries { *; }

# ---- kotlinx.coroutines / serialization ----
-dontwarn kotlinx.coroutines.**
-keepclassmembers class kotlinx.coroutines.** { volatile <fields>; }
-dontwarn kotlinx.serialization.**
-keepclassmembers class kotlinx.serialization.json.** { *** Companion; }
-keepclasseswithmembers class kotlinx.serialization.json.** { kotlinx.serialization.KSerializer serializer(...); }

# ---- enum 反射（EngineCatalog / ManagerCatalog / HomeTab / DeviceModel）----
-keepclassmembers enum com.ghostlock.honorfne.** {
    public static **[] values();
    public static ** valueOf(java.lang.String);
    public static ** entries;
}

# ---- Activity / Service / Provider / Receiver（系统按类名反射创建）----
-keep public class com.ghostlock.honorfne.MainActivity { *; }
-keep public class * extends android.app.Activity { *; }
-keep public class * extends android.app.Service { *; }
-keep public class * extends android.content.ContentProvider { *; }
-keep public class * extends android.content.BroadcastReceiver { *; }

# ---- 崩溃栈里的类名要可读（LogStore 写进 HonorRoot-Log）----
-keepnames class com.ghostlock.honorfne.** { *; }

# ---- Compose ----
-dontwarn androidx.compose.**
-keepclassmembers class androidx.compose.runtime.** { *; }

# ---- 通用：泛型签名与内部类名（Compose 编译器读 KClass）----
-keep,allowobfuscation,allowshrinking class kotlin.Metadata { *; }
-keep,allowobfuscation,allowshrinking class kotlin.enums.EnumEntries { *; }
