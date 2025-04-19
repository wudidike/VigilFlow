import sys
import re
import json
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QGroupBox, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QStatusBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor


class DetectionThread(QThread):
    detection_done = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def __init__(self, http_data, rules):
        super().__init__()
        self.http_data = http_data
        self.rules = rules

    def run(self):
        results = []
        try:
            headers = self._extract_headers()
            for rule in self.rules:
                if rule["name"] == "CORS跨域漏洞":
                    host = headers.get("Host")
                    origin = headers.get("Origin")
                    if host and origin:
                        origin_domain = re.sub(r'^https?://', '', origin).split('/')[0]
                        if host != origin_domain:
                            results.append({
                                "rule_name": f"{rule['name']} (Headers)",
                                "severity": rule["severity"],
                                "matched": True
                            })
                else:
                    targets = [
                        ("URL", self._extract_url()),
                        ("Headers", str(headers)),
                        ("Body", self._extract_body())
                    ]
                    for section, content in targets:
                        if not content:
                            continue
                        try:
                            if re.search(rule["regex"], str(content), re.IGNORECASE):
                                results.append({
                                    "rule_name": f"{rule['name']} ({section})",
                                    "severity": rule["severity"],
                                    "matched": True
                                })
                        except re.error as e:
                            self.error_occurred.emit(f"正则表达式错误 [{rule['name']}]: {str(e)}")
                            continue

            if len(results) > 1:
                results.append({
                    "rule_name": "Composite Attack",
                    "severity": "Critical",
                    "matched": True
                })

        except Exception as e:
            self.error_occurred.emit(f"检测过程异常: {str(e)}")
        finally:
            self.detection_done.emit(results)

    def _extract_url(self):
        match = re.search(r"(GET|POST) (.*?) HTTP", self.http_data)
        return match.group(2) if match else ""

    def _extract_headers(self):
        headers = {}
        for line in self.http_data.split('\n'):
            if ':' in line and not line.startswith(('GET', 'POST')):
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers

    def _extract_body(self):
        parts = self.http_data.split('\n\n', 1)
        return parts[1] if len(parts) > 1 else ""


class CyberSecAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.rules = []
        self.init_ui()
        self.load_rules()

    def init_ui(self):
        self.setWindowTitle("VigilFlow v1.0")
        self.setGeometry(300, 300, 1024, 768)
        self.setStyleSheet(self._load_styles())

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        splitter = QSplitter(Qt.Vertical)

        input_group = QGroupBox("HTTP请求包")
        input_layout = QVBoxLayout()
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("粘贴HTTP请求原始数据...")
        input_layout.addWidget(self.text_input)

        btn_layout = QHBoxLayout()
        self.analyze_btn = QPushButton("🚀 开始检测")
        self.analyze_btn.setObjectName("analyze_btn")
        self.analyze_btn.clicked.connect(self.start_analysis)
        self.clear_btn = QPushButton("✖️ 清空")
        self.clear_btn.setObjectName("clear_btn")
        self.clear_btn.clicked.connect(self.clear_input)
        btn_layout.addWidget(self.analyze_btn)
        btn_layout.addWidget(self.clear_btn)
        input_layout.addLayout(btn_layout)
        input_group.setLayout(input_layout)

        result_group = QGroupBox("检测结果")
        result_layout = QVBoxLayout()
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(3)
        self.result_table.setHorizontalHeaderLabels(["规则名称", "危险等级", "检测状态"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        result_layout.addWidget(self.result_table)
        result_group.setLayout(result_layout)

        splitter.addWidget(input_group)
        splitter.addWidget(result_group)
        splitter.setSizes([300, 500])
        layout.addWidget(splitter)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

    def _load_styles(self):
        return """
            QMainWindow { background-color: #1a1a1a; }
            QGroupBox {
                color: #00ff9d;
                border: 2px solid #00ff9d;
                margin-top: 10px;
                padding-top: 15px;
                font-size: 24px;
            }
            QTextEdit, QTableWidget {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3d3d3d;
                font-family: Consolas;
                font-size: 18px;
            }
            QPushButton {
                padding: 8px;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover { opacity: 0.8; }
            #analyze_btn { background-color: #00ff9d; color: #1a1a1a; }
            #clear_btn { background-color: #ff4757; color: white; }
        """

    def load_rules(self):
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            json_path = os.path.join(base_dir, "attack_rules.json")
            with open(json_path, "r", encoding="utf-8") as f:
                self.rules = json.load(f)
        except Exception as e:
            self.show_status(f"规则加载失败: {str(e)}", "red")

    def start_analysis(self):
        if not self.rules:
            self.show_status("未加载攻击规则!", "red")
            return

        http_data = self.text_input.toPlainText()
        if not http_data.strip():
            self.show_status("请输入HTTP数据!", "red")
            return

        self.analyze_btn.setEnabled(False)
        self.show_status("分析中...", "#00ff9d")

        self.detection_thread = DetectionThread(http_data, self.rules)
        self.detection_thread.detection_done.connect(self.show_results)
        self.detection_thread.error_occurred.connect(self.handle_error)
        self.detection_thread.start()

    def show_results(self, results):
        self.analyze_btn.setEnabled(True)
        self.result_table.setRowCount(0)

        if not results:
            self.show_status("未检测到威胁!", "#00ff9d")
            return

        for result in results:
            row = self.result_table.rowCount()
            self.result_table.insertRow(row)

            color = "#ff4757" if result["matched"] else "#00ff9d"
            items = [
                QTableWidgetItem(result["rule_name"]),
                QTableWidgetItem(result["severity"]),
                QTableWidgetItem("检测到威胁" if result["matched"] else "安全")
            ]

            for i, item in enumerate(items):
                item.setForeground(QColor(color))
                self.result_table.setItem(row, i, item)

        self.show_status(f"检测到 {len(results)} 个潜在威胁!", "#ff4757")

    def handle_error(self, error_msg):
        self.analyze_btn.setEnabled(True)
        self.show_status(error_msg, "red")

    def clear_input(self):
        self.text_input.clear()
        self.result_table.setRowCount(0)
        self.show_status("就绪", "#00ff9d")

    def show_status(self, message, color):
        self.status_bar.showMessage(message)
        self.status_bar.setStyleSheet(f"color: {color};")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("微软雅黑", 14))
    window = CyberSecAnalyzer()
    window.show()
    sys.exit(app.exec_())
