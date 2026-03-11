import os
import sys
import zipfile
import struct
import secrets
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                               QPushButton, QLabel, QLineEdit, QCheckBox, QFileDialog,
                               QProgressBar, QMessageBox, QGroupBox)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import win32cred
import win32con

# --- 配置 ---
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 200000
CHUNK_SIZE = 64 * 1024 * 1024
CRED_NAME = "AES256_File_Tool_Key"
FILE_SIGNATURE = b'AES256'

# --- 核心加解密类 ---
class CryptoCore:
    @staticmethod
    def derive_key(password: str, salt: bytes):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt, iterations=ITERATIONS)
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def encrypt_file(in_path, out_path, password, progress_sig):
        salt = secrets.token_bytes(SALT_SIZE)
        key = CryptoCore.derive_key(password, salt)
        aesgcm = AESGCM(key)
        file_size = os.path.getsize(in_path)
        
        with open(in_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
            f_out.write(FILE_SIGNATURE)
            f_out.write(salt)
            f_out.write(struct.pack('<Q', file_size))
            
            offset = 0
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk: break
                nonce = secrets.token_bytes(NONCE_SIZE)
                ct_tag = aesgcm.encrypt(nonce, chunk, struct.pack('<Q', offset))
                
                f_out.write(nonce)
                f_out.write(struct.pack('<I', len(ct_tag)))
                f_out.write(ct_tag)
                
                offset += len(chunk)
                progress_sig.emit(int(offset / file_size * 100))

    @staticmethod
    def decrypt_file(in_path, out_path, password, progress_sig):
        with open(in_path, 'rb') as f_in:
            if f_in.read(6) != FILE_SIGNATURE:
                raise ValueError("文件格式错误")
            
            salt = f_in.read(16)
            key = CryptoCore.derive_key(password, salt)
            aesgcm = AESGCM(key)
            
            file_size = struct.unpack('<Q', f_in.read(8))[0]
            processed = 0
            
            with open(out_path, 'wb') as f_out:
                while processed < file_size:
                    nonce = f_in.read(12)
                    ct_len = struct.unpack('<I', f_in.read(4))[0]
                    ct_tag = f_in.read(ct_len)
                    
                    plaintext = aesgcm.decrypt(nonce, ct_tag, struct.pack('<Q', processed))
                    f_out.write(plaintext)
                    processed += len(plaintext)
                    progress_sig.emit(int(processed / file_size * 100))

# --- 密钥管理 ---
class KeyManager:
    @staticmethod
    def save(pwd):
        cred = {'Type': win32con.CRED_TYPE_GENERIC, 'TargetName': CRED_NAME, 
                'CredentialBlob': pwd.encode('utf-16-le'), 'Persist': win32con.CRED_PERSIST_LOCAL_MACHINE}
        win32cred.CredWrite(cred, 0)
    @staticmethod
    def load():
        try:
            c = win32cred.CredRead(CRED_NAME, win32con.CRED_TYPE_GENERIC, 0)
            return c['CredentialBlob'].decode('utf-16-le')
        except: return None

# --- 工作线程 ---
class Worker(QThread):
    finished = Signal(bool, str)
    progress = Signal(int)
    def __init__(self, mode, src, dst, pwd, compress):
        super().__init__()
        self.mode, self.src, self.dst, self.pwd, self.compress = mode, src, dst, pwd, compress

    def run(self):
        try:
            work_src = self.src
            temp_zip = None
            
            if self.mode == 'encrypt':
                if os.path.isdir(self.src):
                    if not self.compress: raise Exception("文件夹必须启用压缩")
                    temp_zip = self.dst + ".tmp.zip"
                    with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                        for root, _, files in os.walk(self.src):
                            for f in files:
                                fp = os.path.join(root, f)
                                zf.write(fp, os.path.relpath(fp, self.src))
                    work_src = temp_zip
                
                CryptoCore.encrypt_file(work_src, self.dst, self.pwd, self.progress)
                if temp_zip: os.remove(temp_zip)
                self.finished.emit(True, "加密成功")
            
            else: # decrypt
                temp_out = self.dst + ".tmp"
                CryptoCore.decrypt_file(self.src, temp_out, self.pwd, self.progress)
                
                try:
                    with zipfile.ZipFile(temp_out, 'r') as zf:
                        zf.extractall(self.dst)
                    os.remove(temp_out)
                except:
                    if os.path.exists(self.dst): os.remove(self.dst)
                    os.rename(temp_out, self.dst)
                
                self.finished.emit(True, "解密成功")
                
        except Exception as e:
            self.finished.emit(False, str(e))

# --- 主界面 ---
class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AES-256 加密工具")
        self.resize(500, 400)
        
        # 加载图标
        if os.path.exists("icon.ico"):
            self.setWindowIcon(QIcon("icon.ico"))

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(15)
        layout.setContentsMargins(20,20,20,20)

        # 1. 文件选择（修改：替换为双按钮）
        g1 = QGroupBox("目标")
        l1 = QVBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("选择文件或文件夹...")
        
        # 新增：创建两个浏览按钮
        btn_browse_file = QPushButton("选择文件")
        btn_browse_file.clicked.connect(self.browse_file)
        btn_browse_dir = QPushButton("选择文件夹")
        btn_browse_dir.clicked.connect(self.browse_dir)
        
        # 调整布局：添加两个按钮
        r1 = QHBoxLayout()
        r1.addWidget(self.path_edit)
        r1.addWidget(btn_browse_file)
        r1.addWidget(btn_browse_dir)
        l1.addLayout(r1)
        
        self.cb_compress = QCheckBox("加密前压缩 (推荐文件夹使用)")
        l1.addWidget(self.cb_compress)
        g1.setLayout(l1)
        layout.addWidget(g1)

        # 2. 密钥
        g2 = QGroupBox("密钥")
        l2 = QVBoxLayout()
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("输入密钥 (4-1024位)")
        self.key_edit.setEchoMode(QLineEdit.Password)
        saved_key = KeyManager.load()
        if saved_key: self.key_edit.setText(saved_key)
        l2.addWidget(self.key_edit)
        self.cb_save = QCheckBox("保存密钥到系统凭据")
        self.cb_save.setChecked(bool(saved_key))
        l2.addWidget(self.cb_save)
        g2.setLayout(l2)
        layout.addWidget(g2)

        # 3. 按钮
        r2 = QHBoxLayout()
        self.btn_enc = QPushButton("加密")
        self.btn_enc.setMinimumHeight(40)
        self.btn_enc.clicked.connect(lambda: self.start('encrypt'))
        self.btn_dec = QPushButton("解密")
        self.btn_dec.setMinimumHeight(40)
        self.btn_dec.clicked.connect(lambda: self.start('decrypt'))
        r2.addWidget(self.btn_enc)
        r2.addWidget(self.btn_dec)
        layout.addLayout(r2)

        # 4. 进度
        self.prog = QProgressBar()
        self.prog.setVisible(False)
        layout.addWidget(self.prog)

    # 新增：选择文件方法
    def browse_file(self):
        fp, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if fp:
            self.path_edit.setText(fp)
            self.cb_compress.setChecked(False)  # 选文件自动取消压缩

    # 新增：选择文件夹方法
    def browse_dir(self):
        dp = QFileDialog.getExistingDirectory(self, "选择文件夹")
        if dp:
            self.path_edit.setText(dp)
            self.cb_compress.setChecked(True)   # 选文件夹自动勾选压缩

    def start(self, mode):
        src = self.path_edit.text()
        pwd = self.key_edit.text()
        
        if not os.path.exists(src): return QMessageBox.warning(self, "错误", "路径无效")
        if len(pwd) < 4: return QMessageBox.warning(self, "错误", "密钥太短（至少4位）")

        if self.cb_save.isChecked(): KeyManager.save(pwd)
        
        if mode == 'encrypt':
            dst, _ = QFileDialog.getSaveFileName(self, "保存加密文件到", src + ".enc")
        else:
            dst, _ = QFileDialog.getSaveFileName(self, "保存解密文件到", src.replace(".enc", ""))
        
        if not dst: return

        self._ui(False)
        self.worker = Worker(mode, src, dst, pwd, self.cb_compress.isChecked())
        self.worker.progress.connect(self.prog.setValue)
        self.worker.finished.connect(self._done)
        self.worker.start()

    def _done(self, ok, msg):
        self._ui(True)
        if ok: QMessageBox.information(self, "成功", msg)
        else: QMessageBox.warning(self, "失败", msg)

    def _ui(self, enabled):
        self.btn_enc.setEnabled(enabled)
        self.btn_dec.setEnabled(enabled)
        self.prog.setVisible(not enabled)

# --- 入口 ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = Window()
    w.show()
    sys.exit(app.exec())