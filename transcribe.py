import os
import sys
import datetime
import threading
import traceback
import hashlib
import subprocess
import json
import webbrowser
from pathlib import Path
from collections import deque

import numpy as np
import sounddevice as sd
import librosa
from faster_whisper import WhisperModel
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
import zhconv  # 添加繁简转换库

# ————— 授权验证部分 —————

def get_disk_serial():
    """获取系统主硬盘序列号"""
    try:
        if sys.platform == 'win32':
            # Windows系统使用wmic命令获取
            result = subprocess.check_output('wmic diskdrive get serialnumber', shell=True).decode().strip()
            lines = [line for line in result.split('\n') if line.strip()]
            if len(lines) >= 2:  # 第一行是标题，第二行开始是序列号
                return lines[1].strip()
        elif sys.platform == 'darwin':
            # macOS系统
            result = subprocess.check_output('ioreg -l | grep IOPlatformSerialNumber', 
                                             shell=True).decode().strip()
            return result.split('=')[-1].strip().replace('"', '')
        else:
            # Linux系统
            result = subprocess.check_output('lsblk -d -no serial', shell=True).decode().strip()
            if result:
                return result.split('\n')[0].strip()
            
        # 如果上述方法都失败，使用机器名和CPU信息的组合
        fallback = f"{os.environ.get('COMPUTERNAME', '')}-{subprocess.check_output('wmic cpu get processorid', shell=True).decode().strip() if sys.platform == 'win32' else ''}"
        return hashlib.md5(fallback.encode()).hexdigest()
    except Exception as e:
        print(f"获取硬盘序列号失败: {e}")
        # 使用一个备用方法，根据机器名生成一个伪序列号
        return hashlib.md5(os.environ.get('COMPUTERNAME', 'unknown').encode()).hexdigest()

def generate_license_key(disk_serial, salt="your_secret_salt"):
    """根据硬盘序列号生成授权码"""
    # 将硬盘序列号和盐值组合，使用SHA256生成授权码
    key_material = f"{disk_serial}:{salt}"
    return hashlib.sha256(key_material.encode()).hexdigest()

def verify_license(license_file="license.json"):
    """验证授权文件"""
    try:
        # 获取当前硬盘序列号
        disk_serial = get_disk_serial()
        
        # 检查授权文件是否存在
        license_path = Path(license_file)
        if not license_path.exists():
            return False, "找不到授权文件"
        
        # 读取授权文件
        with open(license_path, "r") as f:
            license_data = json.load(f)
        
        # 检查授权码是否匹配
        expected_license = generate_license_key(disk_serial)
        if license_data.get("license_key") != expected_license:
            return False, "授权无效：硬盘序列号不匹配"
        
        # 检查有效期（如果有）
        if "expires" in license_data:
            expires = datetime.datetime.strptime(license_data["expires"], "%Y-%m-%d")
            if expires < datetime.datetime.now():
                return False, f"授权已过期，有效期至: {license_data['expires']}"
            
            # 如果即将过期（30天内），返回警告
            days_left = (expires - datetime.datetime.now()).days
            if days_left <= 30:
                return True, f"授权即将过期，剩余{days_left}天"
                
        return True, f"授权有效，用户: {license_data.get('user', '未知')}"
        
    except Exception as e:
        return False, f"授权验证失败: {e}"

# ————— 配置参数 —————
SAMPLE_RATE = 16000      # 采样率
WINDOW = 30              # 推理窗口长度（秒）
STEP = 15                # 每隔多少秒做一次推理
OUTPUT_DIR = "transcripts"
LOG_FILE = "log.txt"

# 项目根目录（支持打包后路径识别）
if getattr(sys, 'frozen', False):
    # 如果是打包后的可执行文件
    BASE_DIR = sys._MEIPASS
else:
    # 如果是直接运行脚本
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# 确保models目录的正确路径
MODEL_PATH = os.path.join(BASE_DIR, "models", "medium")
log_file_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), LOG_FILE)

# 初始化
os.makedirs(OUTPUT_DIR, exist_ok=True)
log_lock = threading.Lock()
stop_event = threading.Event()

# 日志函数：打印到文件 + 控制台
def log(msg: str):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{ts}] {msg}"
    print(full_msg)
    with log_lock, open(log_file_path, "a", encoding="utf-8") as f:
        f.write(full_msg + "\n")

# 音频缓冲区
buffer = deque(maxlen=WINDOW * SAMPLE_RATE)
last_log_time = [0]  # 用于节流日志输出

def audio_callback(indata, frames, time, status):
    if status:
        log(f"[音频回调状态] {status}")
    buffer.extend(indata[:, 0].tolist())

    # 每隔5秒记录一次采集状态
    now = datetime.datetime.now().timestamp()
    if now - last_log_time[0] >= 5:
        last_log_time[0] = now
        log(f"[音频采集] 接收到 {frames} 帧音频，缓冲区当前长度：{len(buffer)}")

# 添加繁简转换函数
def to_simplified(text):
    """将任何中文文本转换为简体中文"""
    try:
        return zhconv.convert(text, 'zh-cn')
    except Exception as e:
        log(f"[繁简转换错误] {e}")
        return text  # 转换失败时返回原文本

def transcribe_loop():
    while not stop_event.is_set():
        if len(buffer) >= WINDOW * SAMPLE_RATE:
            log(f"[推理准备] 已采集 {len(buffer)} 样本，开始推理...")
            audio = np.array(buffer, dtype=np.float32)[-WINDOW * SAMPLE_RATE:]
            try:
                segments, _ = model.transcribe(
                    audio,
                    beam_size=10,
                    language="zh",  # 使用"zh"对中文进行识别
                    vad_filter=False
                )
                # 收集转写结果并转为简体中文
                text_parts = []
                for seg in segments:
                    # 将每个片段的文本转换为简体中文
                    simplified_text = to_simplified(seg.text)
                    text_parts.append(simplified_text)
                
                text = "".join(text_parts).strip()
                
                if text:
                    ts = datetime.datetime.now()
                    fname = ts.strftime("%Y-%m-%d_%H") + ".txt"
                    path = os.path.join(OUTPUT_DIR, fname)
                    with open(path, "a", encoding="utf-8") as f:
                        f.write(f"[{ts.strftime('%H:%M:%S')}] {text}\n")
                    log(f"💾 成功转写内容写入：{path}")
                    log(f"📌 内容：{text}")
                else:
                    log("📭 无有效语音内容")
            except Exception as e:
                err = f"[推理错误] {e}\n{traceback.format_exc()}"
                log(err)
                messagebox.showerror("推理错误", err)
        for _ in range(STEP):
            if stop_event.is_set():
                break
            sd.sleep(1000)

def start_recording():
    try:
        stop_event.clear()
        buffer.clear()
        stream.start()
        threading.Thread(target=transcribe_loop, daemon=True).start()
        start_btn.config(state="disabled")
        stop_btn.config(state="normal")
        log("▶️ 开始录音+转写")
    except Exception as e:
        log(f"[启动错误] {e}")
        messagebox.showerror("启动失败", str(e))

def stop_recording():
    try:
        stop_event.set()
        stream.stop()
        start_btn.config(state="normal")
        stop_btn.config(state="disabled")
        log("⏹️ 已停止录音")
    except Exception as e:
        log(f"[停止错误] {e}")
        messagebox.showerror("停止失败", str(e))

def send_license_request():
    """发送授权申请"""
    try:
        disk_serial = get_disk_serial()
        
        # 创建授权申请信息
        info = {
            "serial": disk_serial,
            "username": os.environ.get('USERNAME', 'unknown'),
            "computer": os.environ.get('COMPUTERNAME', 'unknown'),
            "date": datetime.datetime.now().strftime("%Y-%m-%d")
        }
        
        # 创建邮件内容
        email_body = f"""
授权申请信息:

设备序列号: {disk_serial}
用户名: {info['username']}
计算机名: {info['computer']}
申请日期: {info['date']}

请将授权文件发送至此用户邮箱。
        """
        
        # 显示授权申请窗口
        request_window = tk.Toplevel()
        request_window.title("授权申请")
        request_window.geometry("600x400")
        
        tk.Label(request_window, text="设备授权信息", font=("Arial", 14, "bold")).pack(pady=10)
        
        frame = tk.Frame(request_window)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # 显示设备序列号
        serial_frame = tk.Frame(frame)
        serial_frame.pack(fill=tk.X, pady=5)
        tk.Label(serial_frame, text="设备序列号:", width=12, anchor="w").pack(side=tk.LEFT)
        serial_entry = tk.Entry(serial_frame)
        serial_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        serial_entry.insert(0, disk_serial)
        serial_entry.config(state="readonly")
        
        def copy_serial():
            request_window.clipboard_clear()
            request_window.clipboard_append(disk_serial)
            copy_btn.config(text="已复制！")
            request_window.after(2000, lambda: copy_btn.config(text="复制序列号"))
        
        copy_btn = tk.Button(serial_frame, text="复制序列号", command=copy_serial)
        copy_btn.pack(side=tk.RIGHT, padx=5)
        
        # 显示授权申请信息
        tk.Label(frame, text="授权申请信息:", anchor="w").pack(fill=tk.X, pady=5)
        info_text = scrolledtext.ScrolledText(frame, height=10)
        info_text.pack(fill=tk.BOTH, expand=True, pady=5)
        info_text.insert(tk.END, email_body)
        info_text.config(state="disabled")
        
        # 按钮区域
        btn_frame = tk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        def copy_all():
            request_window.clipboard_clear()
            request_window.clipboard_append(email_body)
            copy_all_btn.config(text="已复制！")
            request_window.after(2000, lambda: copy_all_btn.config(text="复制全部信息"))
        
        copy_all_btn = tk.Button(btn_frame, text="复制全部信息", command=copy_all)
        copy_all_btn.pack(side=tk.LEFT, padx=5)
        
        def send_email():
            try:
                # 使用默认邮件客户端打开发送窗口
                email = simpledialog.askstring("输入邮箱", "请输入开发者邮箱地址：", 
                                              parent=request_window)
                if email:
                    webbrowser.open(f"mailto:{email}?subject=语音转写软件授权申请&body={email_body}")
            except Exception as e:
                messagebox.showerror("错误", f"无法打开邮件客户端: {e}")
        
        email_btn = tk.Button(btn_frame, text="发送邮件申请", command=send_email)
        email_btn.pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="关闭", command=request_window.destroy).pack(side=tk.RIGHT, padx=5)
        
    except Exception as e:
        messagebox.showerror("错误", f"生成授权申请失败: {e}")

def on_closing():
    """窗口关闭时的清理工作"""
    try:
        if stop_btn['state'] == 'normal':  # 如果停止按钮可用，说明正在录音
            stop_recording()
        root.destroy()
    except Exception as e:
        log(f"[关闭错误] {e}")
        sys.exit(1)

def create_gui():
    global root, start_btn, stop_btn, stream, model, status_label
    
    # 记录模型路径
    log(f"模型路径: {MODEL_PATH}")
    log(f"当前目录: {os.getcwd()}")
    log(f"BASE_DIR: {BASE_DIR}")
    
    # 检查模型目录是否存在
    if not os.path.exists(MODEL_PATH):
        log(f"⚠️ 模型目录不存在: {MODEL_PATH}")
        dirs = os.listdir(BASE_DIR)
        log(f"BASE_DIR内容: {dirs}")
        if "models" in dirs:
            models_dir = os.path.join(BASE_DIR, "models")
            log(f"models目录内容: {os.listdir(models_dir)}")
    
    # 加载 faster-whisper 模型（使用本地模型）
    try:
        model = WhisperModel(MODEL_PATH, device="cpu", compute_type="int8", local_files_only=True)
        log(f"✅ 模型加载成功：{MODEL_PATH}")
    except Exception as e:
        log(f"[模型加载错误] {e}\n{traceback.format_exc()}")
        messagebox.showerror("模型加载失败", f"{e}")
        sys.exit(1)

    # 创建输入流
    stream = sd.InputStream(
        samplerate=SAMPLE_RATE,
        channels=1,
        dtype="float32",
        callback=audio_callback
    )

    # ————— GUI 部分 —————
    root = tk.Tk()
    root.title("无缝实时转写（简体中文版）")  # 修改标题以反映简体中文功能
    root.protocol("WM_DELETE_WINDOW", on_closing)  # 处理窗口关闭事件
    
    # 验证授权状态
    is_licensed, license_msg = verify_license()

    # 主框架
    main_frame = tk.Frame(root, padx=15, pady=10)
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # 顶部区域（状态显示）
    top_frame = tk.Frame(main_frame)
    top_frame.pack(fill=tk.X, pady=5)
    
    # 状态标签
    status_text = "授权状态: " + license_msg
    status_color = "green" if is_licensed else "red"
    status_label = tk.Label(top_frame, text=status_text, fg=status_color)
    status_label.pack(side=tk.LEFT, pady=5)
    
    # 语言模式标签
    lang_label = tk.Label(top_frame, text="当前模式: 简体中文", fg="blue")
    lang_label.pack(side=tk.RIGHT, pady=5)
    
    # 如果未授权，显示申请授权按钮
    if not is_licensed:
        license_btn = tk.Button(top_frame, text="申请授权", command=send_license_request)
        license_btn.pack(side=tk.RIGHT, padx=5)
    
    # 录音控制区域
    if is_licensed:
        control_frame = tk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=10)
        
        start_btn = tk.Button(control_frame, text="开始录音+转写", command=start_recording)
        start_btn.pack(side=tk.LEFT, padx=5)
        
        stop_btn = tk.Button(control_frame, text="停止", command=stop_recording, state="disabled")
        stop_btn.pack(side=tk.LEFT, padx=5)
        
        # 添加简体中文模式说明
        tk.Label(control_frame, text="* 所有识别文本将自动转换为简体中文", fg="gray").pack(side=tk.LEFT, padx=10)
    
    # 如果未授权，显示提示信息
    else:
        info_frame = tk.Frame(main_frame)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        info_text = """
软件未授权或授权已过期！

请点击"申请授权"按钮获取您的设备序列号，
并将此序列号发送给软件开发者以获取授权文件。

获得授权文件后，请将其放置在程序同一目录下，
文件名必须为"license.json"。
        """
        
        info_label = tk.Label(info_frame, text=info_text, justify=tk.LEFT, 
                              padx=20, pady=20, relief=tk.GROOVE)
        info_label.pack(fill=tk.BOTH, expand=True)

    root.mainloop()

def show_license_manager():
    """显示授权管理窗口"""
    disk_serial = get_disk_serial()
    license_key = generate_license_key(disk_serial)
    
    # 创建窗口
    manager_win = tk.Tk()
    manager_win.title("授权管理工具")
    manager_win.geometry("600x500")
    
    # 创建标题
    tk.Label(manager_win, text="语音转写软件授权管理", font=("Arial", 16, "bold")).pack(pady=10)
    
    # 主框架
    main_frame = tk.Frame(manager_win)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    # 设备信息区域
    info_frame = tk.LabelFrame(main_frame, text="设备信息")
    info_frame.pack(fill=tk.X, pady=10)
    
    # 序列号显示
    serial_frame = tk.Frame(info_frame)
    serial_frame.pack(fill=tk.X, pady=5, padx=10)
    tk.Label(serial_frame, text="硬盘序列号:", width=12, anchor="w").pack(side=tk.LEFT)
    serial_entry = tk.Entry(serial_frame)
    serial_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    serial_entry.insert(0, disk_serial)
    serial_entry.config(state="readonly")
    
    def copy_serial():
        manager_win.clipboard_clear()
        manager_win.clipboard_append(disk_serial)
        copy_serial_btn.config(text="已复制！")
        manager_win.after(2000, lambda: copy_serial_btn.config(text="复制序列号"))
    
    copy_serial_btn = tk.Button(serial_frame, text="复制序列号", command=copy_serial)
    copy_serial_btn.pack(side=tk.RIGHT)
    
    # 授权码显示
    key_frame = tk.Frame(info_frame)
    key_frame.pack(fill=tk.X, pady=5, padx=10)
    tk.Label(key_frame, text="生成的授权码:", width=12, anchor="w").pack(side=tk.LEFT)
    key_entry = tk.Entry(key_frame)
    key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    key_entry.insert(0, license_key)
    key_entry.config(state="readonly")
    
    def copy_key():
        manager_win.clipboard_clear()
        manager_win.clipboard_append(license_key)
        copy_key_btn.config(text="已复制！")
        manager_win.after(2000, lambda: copy_key_btn.config(text="复制授权码"))
    
    copy_key_btn = tk.Button(key_frame, text="复制授权码", command=copy_key)
    copy_key_btn.pack(side=tk.RIGHT)
    
    # 授权状态区域
    status_frame = tk.LabelFrame(main_frame, text="授权状态")
    status_frame.pack(fill=tk.X, pady=10)
    
    # 检查当前授权状态
    is_licensed, license_msg = verify_license()
    status_color = "green" if is_licensed else "red"
    
    status_label = tk.Label(status_frame, text=license_msg, fg=status_color, padx=10, pady=10)
    status_label.pack(fill=tk.X)
    
    # 授权操作区域
    action_frame = tk.LabelFrame(main_frame, text="授权操作")
    action_frame.pack(fill=tk.BOTH, expand=True, pady=10)
    
    # 导出授权信息按钮
    def export_info():
        try:
            filename = f"license_request_{os.environ.get('USERNAME', 'user')}_{datetime.datetime.now().strftime('%Y%m%d')}.txt"
            with open(filename, "w") as f:
                f.write(f"设备序列号: {disk_serial}\n")
                f.write(f"用户名: {os.environ.get('USERNAME', 'unknown')}\n")
                f.write(f"计算机名: {os.environ.get('COMPUTERNAME', 'unknown')}\n")
                f.write(f"申请日期: {datetime.datetime.now().strftime('%Y-%m-%d')}\n")
            
            messagebox.showinfo("成功", f"授权申请信息已导出到: {filename}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")
    
    export_btn = tk.Button(action_frame, text="导出授权申请信息", command=export_info)
    export_btn.pack(anchor="w", padx=10, pady=5)
    
    # 重新验证授权按钮
    def reverify():
        is_licensed, license_msg = verify_license()
        status_color = "green" if is_licensed else "red"
        status_label.config(text=license_msg, fg=status_color)
    
    verify_btn = tk.Button(action_frame, text="重新验证授权", command=reverify)
    verify_btn.pack(anchor="w", padx=10, pady=5)
    
    # 创建空授权文件模板按钮
    def create_template():
        try:
            template = {
                "license_key": "在此处填入正确的授权码",
                "device_id": disk_serial,
                "created": datetime.datetime.now().strftime("%Y-%m-%d"),
                "expires": (datetime.datetime.now() + datetime.timedelta(days=365)).strftime("%Y-%m-%d"),
                "user": os.environ.get('USERNAME', 'unknown')
            }
            
            with open("license_template.json", "w") as f:
                json.dump(template, f, indent=4)
                
            messagebox.showinfo("成功", "授权文件模板已创建: license_template.json")
        except Exception as e:
            messagebox.showerror("错误", f"创建模板失败: {e}")
    
    template_btn = tk.Button(action_frame, text="创建授权文件模板", command=create_template)
    template_btn.pack(anchor="w", padx=10, pady=5)
    
    # 底部按钮
    btn_frame = tk.Frame(manager_win)
    btn_frame.pack(fill=tk.X, pady=10, padx=20)
    
    close_btn = tk.Button(btn_frame, text="关闭", command=manager_win.destroy)
    close_btn.pack(side=tk.RIGHT)
    
    help_text = """
使用说明:
1. 复制您的硬盘序列号，发送给软件开发者
2. 开发者会生成对应的授权文件并发送给您
3. 将授权文件(license.json)放在程序同一目录下
4. 重新启动程序，即可正常使用
    """
    
    help_label = tk.Label(main_frame, text=help_text, justify=tk.LEFT, 
                          relief=tk.GROOVE, padx=10, pady=10)
    help_label.pack(fill=tk.X, pady=10)
    
    manager_win.mainloop()

if __name__ == "__main__":
    # 添加命令行参数支持
    if len(sys.argv) > 1:
        if sys.argv[1] == "--license-info" or sys.argv[1] == "--license":
            # 显示授权管理窗口
            show_license_manager()
            sys.exit(0)
        
    # 验证授权
    is_licensed, license_msg = verify_license()
    
    if not is_licensed:
        # 即使未授权也创建GUI，但禁用主要功能
        log(f"⚠️ 授权验证失败: {license_msg}")
    else:
        log(f"✅ 授权验证成功: {license_msg}")
    
    # 创建GUI（无论是否授权）
    create_gui()