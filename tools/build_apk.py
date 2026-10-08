#!/usr/bin/env python3
"""构建 NBX Android APK (Flet GUI + nbx 协议栈)。

用法: .venv/bin/python tools/build_apk.py
前置: .venv 里有 flet; 首次运行会下载 Android SDK/JDK (~2-3GB)
产物: app/build/flutter/build/app/outputs/flutter-apk/
"""
import shutil
import subprocess, sys, os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, "app")

def main():
    env = dict(os.environ)
    env.setdefault("JAVA_HOME", "")
    # flet 1.0.3 模板的 dependency_overrides jni:1.0.0 与 jni_flutter 1.0.4+1
    # (要求 >=1.1.0) 冲突 → 2026-10-07 起使用本地补丁过的模板 zip:
    #   ~/.flet/cache/build-template/v1.0.3/flet-build-template.zip
    #   (dependency_overrides 增加 jni_flutter: 1.0.1)
    # 若 flet 升级后模板重新下载, 需重打补丁:
    #   1. 解开 zip, 编辑 build/{{cookiecutter.out_dir}}/pubspec.yaml
    #      dependency_overrides 加 jni_flutter: 1.0.1
    #   2. 重打包, 第一条 zip 记录必须是目录条目 'build/'
    #   3. 覆盖回 cache 路径
    #
    # nbx 协议栈必须复制到 app/nbx 才会随 app.zip 打包
    # (--include 是"豁免默认排除", 不是"额外打包路径"):
    #   rm -rf app/nbx && cp -r nbx app/nbx && find app/nbx -name __pycache__ -exec rm -rf {} +
    cmd = [os.path.join(REPO, ".venv", "bin", "flet"), "build", "apk",
           "--org", "com.nebula", "--project", "nbxmessenger",
           "--product", "NBX Messenger",
           "--description", "NBX 端到端加密即时通讯",
           "--arch", "arm64-v8a"]
    if os.path.isdir(os.path.join(REPO, "nbx")):
        nbx_dst = os.path.join(APP, "nbx")
        src_files = []
        for root, dirs, files in os.walk(os.path.join(REPO, "nbx")):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for f in files:
                src_files.append(os.path.relpath(os.path.join(root, f),
                                                 os.path.join(REPO, "nbx")))
        dst_files = []
        if os.path.isdir(nbx_dst):
            for root, dirs, files in os.walk(nbx_dst):
                dirs[:] = [d for d in dirs if d != "__pycache__"]
                for f in files:
                    dst_files.append(os.path.relpath(os.path.join(root, f), nbx_dst))
        if src_files != dst_files:
            shutil.rmtree(nbx_dst, ignore_errors=True)
            shutil.copytree(os.path.join(REPO, "nbx"), nbx_dst,
                            ignore=shutil.ignore_patterns("__pycache__"))
            print("synced nbx -> app/nbx (%d files)" % len(src_files))
    print("RUN:", " ".join(cmd), "cwd=app")
    r = subprocess.run(cmd, cwd=APP, env=env)
    apk = os.path.join(APP, "build/flutter/build/app/outputs/flutter-apk",
                       "app-release.apk")
    if r.returncode == 0 and os.path.exists(apk):
        print("APK:", apk, os.path.getsize(apk), "bytes")
    sys.exit(r.returncode)

if __name__ == "__main__":
    main()
