import sys
import threading
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QTableWidget, QTableWidgetItem, QPushButton,
    QLabel, QLineEdit, QComboBox, QTabWidget, QHeaderView,
    QFrame, QSpinBox, QTextEdit, QCheckBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QColor, QFont

from hasher import Hasher, estimate_crack_time, GUESS_RATES
from cracker import DictionaryCracker, BruteForceCracker, write_builtin_wordlist
from external import HashcatRunner, JohnRunner, check_tools, DEFAULT_ROCKYOU


BG_PRIMARY   = "#000000"
BG_SECONDARY = "#111111"
BG_PANEL     = "#1a1a1a"
BG_ROW_ALT   = "#0d0d0d"

FG_PRIMARY   = "#ffffff"
FG_SECONDARY = "#bbbbbb"
FG_DIM       = "#666666"

BORDER       = "#333333"
BORDER_LIGHT = "#444444"

FONT_SIZE = 11

GLOBAL_STYLE = f"""
    * {{
        font-family: Arial, 'Sans-Serif', 'Monospace';
        font-size: {FONT_SIZE}px;
    }}
    QMainWindow, QWidget {{
        background-color: {BG_PRIMARY};
        color: {FG_PRIMARY};
    }}
    QTabWidget::pane {{
        border: 1px solid {BORDER};
        background: {BG_PRIMARY};
    }}
    QTabBar::tab {{
        background: {BG_SECONDARY};
        color: {FG_SECONDARY};
        padding: 8px 24px;
        border: 1px solid {BORDER};
    }}
    QTabBar::tab:selected {{
        background: {BG_PANEL};
        color: {FG_PRIMARY};
        border-bottom: 2px solid {FG_PRIMARY};
    }}
    QTableWidget {{
        background: {BG_SECONDARY};
        gridline-color: {BORDER};
        border: 1px solid {BORDER};
        color: {FG_PRIMARY};
    }}
    QTableWidget::item {{ padding: 5px 8px; }}
    QTableWidget::item:selected {{ background: {BG_PANEL}; color: {FG_PRIMARY}; }}
    QHeaderView::section {{
        background: #1f1f1f;
        color: {FG_SECONDARY};
        padding: 6px 8px;
        border: 1px solid {BORDER};
        font-weight: bold;
    }}
    QPushButton {{
        background: {BG_PANEL};
        color: {FG_PRIMARY};
        border: 1px solid {BORDER_LIGHT};
        border-radius: 2px;
        padding: 6px 16px;
    }}
    QPushButton:hover {{ background: #2a2a2a; border-color: {FG_SECONDARY}; }}
    QPushButton:pressed {{ background: #333333; }}
    QPushButton#primary_btn {{ border: 1px solid {FG_PRIMARY}; color: {FG_PRIMARY}; }}
    QPushButton#dim_btn {{ border: 1px solid #666666; color: #aaaaaa; }}
    QLineEdit, QSpinBox {{
        background: {BG_SECONDARY};
        color: {FG_PRIMARY};
        border: 1px solid {BORDER_LIGHT};
        border-radius: 2px;
        padding: 5px 8px;
    }}
    QLineEdit:focus, QSpinBox:focus {{ border-color: {FG_PRIMARY}; }}
    QComboBox {{
        background: {BG_SECONDARY};
        color: {FG_PRIMARY};
        border: 1px solid {BORDER_LIGHT};
        border-radius: 2px;
        padding: 5px 8px;
    }}
    QComboBox QAbstractItemView {{
        background: {BG_PANEL};
        color: {FG_PRIMARY};
        border: 1px solid {BORDER_LIGHT};
        selection-background-color: #2a2a2a;
    }}
    QTextEdit {{
        background: {BG_SECONDARY};
        color: {FG_SECONDARY};
        border: 1px solid {BORDER};
        padding: 6px;
    }}
    QCheckBox {{ color: {FG_PRIMARY}; }}
    QScrollBar:vertical {{ background: {BG_SECONDARY}; width: 10px; border: none; }}
    QScrollBar::handle:vertical {{ background: {BORDER_LIGHT}; min-height: 20px; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
"""


class Signals(QObject):
    hash_generated  = pyqtSignal(dict)
    crack_progress  = pyqtSignal(str)
    crack_result    = pyqtSignal(dict)
    benchmark_row   = pyqtSignal(dict)


class StatCard(QFrame):
    def __init__(self, title, value="-"):
        super().__init__()
        self.setFrameShape(QFrame.Box)
        self.setStyleSheet(f"""
            QFrame {{ background: {BG_SECONDARY}; border: 1px solid {BORDER_LIGHT};
                      border-radius: 2px; padding: 12px; }}
        """)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        self.value_label = QLabel(value)
        self.value_label.setFont(QFont("Arial", 20, QFont.Bold))
        self.value_label.setStyleSheet(f"color: {FG_PRIMARY}; border: none;")
        self.value_label.setAlignment(Qt.AlignCenter)
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {FG_DIM}; font-size: 10px; border: none;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.value_label)
        layout.addWidget(title_label)

    def set_value(self, value):
        self.value_label.setText(str(value))


class SectionLabel(QLabel):
    def __init__(self, text):
        super().__init__(text)
        self.setStyleSheet(
            f"color: {FG_SECONDARY}; font-size: 10px; "
            f"padding: 6px 0px 2px 0px; border: none; letter-spacing: 1px;"
        )


class CrackerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Cracking and Hashing")
        self.setMinimumSize(1150, 780)
        self.setStyleSheet(GLOBAL_STYLE)

        self.hasher = Hasher()
        self.tools  = check_tools()
        self.wordlist_path = DEFAULT_ROCKYOU if self.tools["rockyou"] else write_builtin_wordlist()
        self.signals = Signals()

        self.current_hash = None
        self.current_algorithm = None
        self.current_salt = ""

        self.signals.crack_result.connect(self.on_crack_result)
        self.signals.benchmark_row.connect(self.on_benchmark_row)

        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(20, 20, 20, 20)

        header_row = QHBoxLayout()
        title = QLabel("PASSWORD CRACKING AND HASHING")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setStyleSheet(f"color: {FG_PRIMARY}; letter-spacing: 2px;")
        subtitle = QLabel(
            f"hashcat: {'found' if self.tools['hashcat'] else 'missing'}   "
            f"john: {'found' if self.tools['john'] else 'missing'}   "
            f"rockyou: {'found' if self.tools['rockyou'] else 'using builtin list'}"
        )
        subtitle.setStyleSheet(f"color: {FG_DIM}; font-size: 10px;")
        subtitle.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        header_row.addWidget(title)
        header_row.addStretch()
        header_row.addWidget(subtitle)
        main_layout.addLayout(header_row)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet(f"color: {BORDER};")
        main_layout.addWidget(line)

        tabs = QTabWidget()
        tabs.addTab(self._build_hash_tab(),      "HASH GENERATOR")
        tabs.addTab(self._build_crack_tab(),     "CRACK")
        tabs.addTab(self._build_benchmark_tab(), "BENCHMARK")
        tabs.addTab(self._build_salting_tab(),   "WHY SALTING MATTERS")
        main_layout.addWidget(tabs)

    def _build_hash_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(10)

        layout.addWidget(SectionLabel("GENERATE A HASH"))
        row = QHBoxLayout()
        self.h_password = QLineEdit()
        self.h_password.setPlaceholderText("Enter a password to hash")
        self.h_algorithm = QComboBox()
        self.h_algorithm.addItems(["MD5", "SHA1", "SHA256", "SHA256+SALT", "BCRYPT"])
        gen_btn = QPushButton("Generate")
        gen_btn.setObjectName("primary_btn")
        gen_btn.clicked.connect(self.generate_hash)
        row.addWidget(self.h_password)
        row.addWidget(self.h_algorithm)
        row.addWidget(gen_btn)
        layout.addLayout(row)

        self.hash_output = QTextEdit()
        self.hash_output.setReadOnly(True)
        self.hash_output.setMaximumHeight(160)
        layout.addWidget(self.hash_output)

        layout.addWidget(SectionLabel("ESTIMATED BRUTE FORCE TIME (8 char, full charset)"))
        self.estimate_table = QTableWidget(0, 3)
        self.estimate_table.setHorizontalHeaderLabels(["ALGORITHM", "GUESSES/SEC", "WORST CASE TIME"])
        self.estimate_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.estimate_table.verticalHeader().setVisible(False)
        self.estimate_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.estimate_table)
        self._populate_estimates()

        return w

    def _populate_estimates(self):
        self.estimate_table.setRowCount(0)
        for algo, rate in GUESS_RATES.items():
            est = estimate_crack_time(algo, 95, 8, rate)
            row = self.estimate_table.rowCount()
            self.estimate_table.insertRow(row)
            bg = QColor(BG_SECONDARY) if row % 2 == 0 else QColor(BG_ROW_ALT)
            cells = [algo, f"{rate:,}", est["readable"]]
            for col, val in enumerate(cells):
                item = QTableWidgetItem(val)
                item.setBackground(bg)
                item.setForeground(QColor(FG_PRIMARY))
                self.estimate_table.setItem(row, col, item)

    def generate_hash(self):
        password = self.h_password.text()
        if not password:
            return
        algo = self.h_algorithm.currentText()
        fn_map = {
            "MD5": self.hasher.md5,
            "SHA1": self.hasher.sha1,
            "SHA256": self.hasher.sha256,
            "SHA256+SALT": self.hasher.sha256_salted,
            "BCRYPT": self.hasher.bcrypt_hash,
        }
        result = fn_map[algo](password)

        self.current_hash = result["hash"]
        self.current_algorithm = algo
        self.current_salt = result.get("salt", "")

        text = f"Algorithm : {result['algorithm']}\n"
        text += f"Hash      : {result['hash']}\n"
        if result.get("salted"):
            text += f"Salt      : {result.get('salt','')}\n"
        text += f"Speed     : {result['speed_class']}\n\n"
        text += f"Note: {result['note']}"
        self.hash_output.setPlainText(text)

    def _build_crack_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(10)

        layout.addWidget(SectionLabel(
            "TARGET HASH  (use the hash generated in the previous tab, or paste your own)"
        ))
        row = QHBoxLayout()
        self.c_hash_input = QLineEdit()
        self.c_hash_input.setPlaceholderText("Target hash")
        self.c_algorithm = QComboBox()
        self.c_algorithm.addItems(["MD5", "SHA1", "SHA256"])
        use_btn = QPushButton("Use Generated Hash")
        use_btn.clicked.connect(self.load_generated_hash)
        row.addWidget(self.c_hash_input)
        row.addWidget(self.c_algorithm)
        row.addWidget(use_btn)
        layout.addLayout(row)

        layout.addWidget(SectionLabel("METHOD"))
        method_row = QHBoxLayout()
        self.c_method = QComboBox()
        self.c_method.addItems([
            "Custom: Dictionary (built-in list)",
            "Custom: Dictionary + Rules (leet, suffixes, case)",
            "Custom: Brute Force (max 4 chars)",
            "External: hashcat",
            "External: john the ripper",
        ])
        crack_btn = QPushButton("Start Crack")
        crack_btn.setObjectName("primary_btn")
        crack_btn.clicked.connect(self.start_crack)
        method_row.addWidget(self.c_method)
        method_row.addWidget(crack_btn)
        layout.addLayout(method_row)

        self.crack_output = QTextEdit()
        self.crack_output.setReadOnly(True)
        layout.addWidget(self.crack_output)

        return w

    def load_generated_hash(self):
        if self.current_hash and self.current_algorithm in ("MD5", "SHA1", "SHA256"):
            self.c_hash_input.setText(self.current_hash)
            idx = self.c_algorithm.findText(self.current_algorithm)
            if idx >= 0:
                self.c_algorithm.setCurrentIndex(idx)
        else:
            self.crack_output.setPlainText(
                "Generate an MD5, SHA1, or SHA256 hash first.\n"
                "BCRYPT and salted hashes are not supported by the fast crack demo - "
                "see the Why Salting Matters tab for that comparison."
            )

    def start_crack(self):
        target_hash = self.c_hash_input.text().strip()
        algorithm = self.c_algorithm.currentText()
        method = self.c_method.currentText()

        if not target_hash:
            self.crack_output.setPlainText("Enter or load a target hash first.")
            return

        self.crack_output.setPlainText(f"Running: {method}\nTarget: {target_hash}\n\nWorking...")

        def run():
            start_text = f"Method: {method}\nTarget hash: {target_hash}\nAlgorithm: {algorithm}\n\n"

            if method.startswith("Custom: Dictionary (built-in"):
                cracker = DictionaryCracker(self.wordlist_path, use_rules=False, max_words=50000)
                result = cracker.crack(target_hash, algorithm).to_dict()
                result["engine"] = "Custom Python Dictionary"

            elif method.startswith("Custom: Dictionary + Rules"):
                cracker = DictionaryCracker(self.wordlist_path, use_rules=True, max_words=5000)
                result = cracker.crack(target_hash, algorithm).to_dict()
                result["engine"] = "Custom Python Dictionary + Rules"

            elif method.startswith("Custom: Brute Force"):
                cracker = BruteForceCracker()
                result = cracker.crack(target_hash, algorithm, max_length=4).to_dict()
                result["engine"] = "Custom Python Brute Force"

            elif method.startswith("External: hashcat"):
                runner = HashcatRunner(self.wordlist_path)
                result = runner.crack(target_hash, algorithm, timeout=60)
                result["engine"] = "hashcat"

            elif method.startswith("External: john"):
                runner = JohnRunner(self.wordlist_path)
                result = runner.crack(target_hash, algorithm, timeout=60)
                result["engine"] = "john the ripper"

            else:
                result = {"engine": "unknown", "found": False}

            result["_start_text"] = start_text
            self.signals.crack_result.emit(result)

        threading.Thread(target=run, daemon=True).start()

    def on_crack_result(self, result):
        text = result.get("_start_text", "")

        if result.get("available") is False:
            text += f"Tool not available: {result.get('error','')}\n"
            self.crack_output.setPlainText(text)
            return

        if result.get("found"):
            text += f"RESULT: PASSWORD FOUND\n"
            text += f"Password : {result.get('password')}\n"
        else:
            text += f"RESULT: NOT FOUND\n"

        if "attempts" in result:
            text += f"Attempts : {result.get('attempts')}\n"
        if "elapsed" in result:
            text += f"Time     : {result.get('elapsed')}s\n"
        if "rate" in result:
            text += f"Rate     : {result.get('rate')} guesses/sec\n"
        if "command" in result:
            text += f"\nCommand used:\n{result.get('command')}\n"

        self.crack_output.setPlainText(text)

    def _build_benchmark_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(10)

        layout.addWidget(SectionLabel("COMPARE ALL ENGINES AGAINST ONE PASSWORD"))
        row = QHBoxLayout()
        self.b_password = QLineEdit()
        self.b_password.setPlaceholderText("Password to benchmark (try something in rockyou, e.g. 'password1')")
        self.b_algorithm = QComboBox()
        self.b_algorithm.addItems(["MD5", "SHA1", "SHA256"])
        run_btn = QPushButton("Run Benchmark")
        run_btn.setObjectName("primary_btn")
        run_btn.clicked.connect(self.run_benchmark)
        row.addWidget(self.b_password)
        row.addWidget(self.b_algorithm)
        row.addWidget(run_btn)
        layout.addLayout(row)

        self.benchmark_table = QTableWidget(0, 5)
        self.benchmark_table.setHorizontalHeaderLabels(
            ["ENGINE", "FOUND", "PASSWORD", "TIME (s)", "ATTEMPTS"]
        )
        self.benchmark_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.benchmark_table.verticalHeader().setVisible(False)
        self.benchmark_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.benchmark_table)

        return w

    def run_benchmark(self):
        password = self.b_password.text().strip()
        algorithm = self.b_algorithm.currentText()
        if not password:
            return

        self.benchmark_table.setRowCount(0)

        fn_map = {"MD5": self.hasher.md5, "SHA1": self.hasher.sha1, "SHA256": self.hasher.sha256}
        target_hash = fn_map[algorithm](password)["hash"]

        def run():
            cracker = DictionaryCracker(self.wordlist_path, use_rules=False, max_words=50000)
            r = cracker.crack(target_hash, algorithm).to_dict()
            self.signals.benchmark_row.emit({"engine": "Custom Python Dictionary", **r})

            cracker = DictionaryCracker(self.wordlist_path, use_rules=True, max_words=5000)
            r = cracker.crack(target_hash, algorithm).to_dict()
            self.signals.benchmark_row.emit({"engine": "Custom Python + Rules", **r})

            if self.tools["hashcat"]:
                runner = HashcatRunner(self.wordlist_path)
                r = runner.crack(target_hash, algorithm, timeout=45)
                self.signals.benchmark_row.emit({"engine": "hashcat", **r})

            if self.tools["john"]:
                runner = JohnRunner(self.wordlist_path)
                r = runner.crack(target_hash, algorithm, timeout=45)
                self.signals.benchmark_row.emit({"engine": "john the ripper", **r})

        threading.Thread(target=run, daemon=True).start()

    def on_benchmark_row(self, result):
        row = self.benchmark_table.rowCount()
        self.benchmark_table.insertRow(row)
        bg = QColor(BG_SECONDARY) if row % 2 == 0 else QColor(BG_ROW_ALT)

        found = "YES" if result.get("found") else ("N/A" if result.get("available") is False else "no")
        cells = [
            result.get("engine", "?"),
            found,
            result.get("password") or "-",
            str(result.get("elapsed", "-")),
            str(result.get("attempts", "-")),
        ]
        for col, val in enumerate(cells):
            item = QTableWidgetItem(val)
            item.setBackground(bg)
            item.setForeground(QColor(FG_PRIMARY))
            if col == 1 and found == "YES":
                item.setFont(QFont("Arial", FONT_SIZE, QFont.Bold))
            self.benchmark_table.setItem(row, col, item)

    def _build_salting_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(10)

        layout.addWidget(SectionLabel("SALTING AND SLOW HASH DEMONSTRATION"))
        row = QHBoxLayout()
        self.s_password = QLineEdit()
        self.s_password.setPlaceholderText("Password to demonstrate")
        self.s_password.setText("Summer2024!")
        run_btn = QPushButton("Run Demonstration")
        run_btn.setObjectName("primary_btn")
        run_btn.clicked.connect(self.run_salting_demo)
        row.addWidget(self.s_password)
        row.addWidget(run_btn)
        layout.addLayout(row)

        self.salting_output = QTextEdit()
        self.salting_output.setReadOnly(True)
        layout.addWidget(self.salting_output)

        return w

    def run_salting_demo(self):
        password = self.s_password.text().strip()
        if not password:
            return

        unsalted_1 = self.hasher.sha256(password)["hash"]
        unsalted_2 = self.hasher.sha256(password)["hash"]
        salted_1 = self.hasher.sha256_salted(password)
        salted_2 = self.hasher.sha256_salted(password)

        text = f"Password: {password}\n\n"
        text += "WITHOUT SALT\n"
        text += f"  Hash run 1 : {unsalted_1}\n"
        text += f"  Hash run 2 : {unsalted_2}\n"
        text += f"  Identical  : {unsalted_1 == unsalted_2}\n"
        text += "  A precomputed rainbow table works against every account "
        text += "using this password, instantly.\n\n"

        text += "WITH SALT\n"
        text += f"  Hash run 1 : {salted_1['hash']}   (salt={salted_1['salt']})\n"
        text += f"  Hash run 2 : {salted_2['hash']}   (salt={salted_2['salt']})\n"
        text += f"  Identical  : {salted_1['hash'] == salted_2['hash']}\n"
        text += "  Every hash is unique even for the same password. Rainbow tables "
        text += "become useless. An attacker must brute force each hash individually.\n\n"

        text += "Computing speed comparison:\n"
        import time
        start = time.time()
        self.hasher.bcrypt_hash(password, rounds=12)
        bcrypt_time = time.time() - start

        text += f"  One SHA256 hash  : ~0.000001 seconds\n"
        text += f"  One BCRYPT hash  : {bcrypt_time:.4f} seconds\n"
        ratio = bcrypt_time / 0.000001
        text += f"  BCRYPT is roughly {ratio:,.0f}x slower per hash.\n\n"
        text += "Across a 14 million word dictionary, that difference is the entire "
        text += "reason bcrypt/scrypt/argon2 are used for real password storage "
        text += "instead of raw SHA256 or MD5."

        self.salting_output.setPlainText(text)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = CrackerGUI()
    window.show()
    sys.exit(app.exec_())
