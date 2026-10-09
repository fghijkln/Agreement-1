import shutil
import subprocess, sys, os
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, 'app')

def main():
    env = dict(os.environ)
    env.setdefault('JAVA_HOME', '')
    cmd = [os.path.join(REPO, '.venv', 'bin', 'flet'), 'build', 'apk', '--org', 'com.nebula', '--project', 'nbxmessenger', '--product', 'NBX Messenger', '--description', 'NBX 端到端加密即时通讯', '--arch', 'arm64-v8a']
    if os.path.isdir(os.path.join(REPO, 'nbx')):
        nbx_dst = os.path.join(APP, 'nbx')
        src_files = []
        for root, dirs, files in os.walk(os.path.join(REPO, 'nbx')):
            dirs[:] = [d for d in dirs if d != '__pycache__']
            for f in files:
                src_files.append(os.path.relpath(os.path.join(root, f), os.path.join(REPO, 'nbx')))
        dst_files = []
        if os.path.isdir(nbx_dst):
            for root, dirs, files in os.walk(nbx_dst):
                dirs[:] = [d for d in dirs if d != '__pycache__']
                for f in files:
                    dst_files.append(os.path.relpath(os.path.join(root, f), nbx_dst))
        if src_files != dst_files:
            shutil.rmtree(nbx_dst, ignore_errors=True)
            shutil.copytree(os.path.join(REPO, 'nbx'), nbx_dst, ignore=shutil.ignore_patterns('__pycache__'))
            print('synced nbx -> app/nbx (%d files)' % len(src_files))
    print('RUN:', ' '.join(cmd), 'cwd=app')
    r = subprocess.run(cmd, cwd=APP, env=env)
    apk = os.path.join(APP, 'build/flutter/build/app/outputs/flutter-apk', 'app-release.apk')
    if r.returncode == 0 and os.path.exists(apk):
        print('APK:', apk, os.path.getsize(apk), 'bytes')
    sys.exit(r.returncode)
if __name__ == '__main__':
    main()
