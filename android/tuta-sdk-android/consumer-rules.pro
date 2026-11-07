# JNA reads the generated bindings' Structure fields and Callback methods by
# reflection, and looks its own classes up by name.
-dontwarn java.awt.**
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }
-keep class org.tunaos.tuta.ffi.** { *; }
