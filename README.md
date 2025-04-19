# VigilFlow
网络安全分析的流量研判工具，专为安全运营/安全运维工程师设计。通过深度解析HTTP流量特征，结合可扩展的威胁规则库，实现针对常见Web攻击的实时检测

vigilflow 与attack_rules.json放在同意文件夹下使用，attack_rules.json可以自行拓展（目前规则库仅支持20+种攻击检测不是很全面💔）

# 检测示例（CORS漏洞请求）
$ python vigilflow.py 
![image](https://github.com/user-attachments/assets/91320921-228e-439c-9466-e3e72c95a6f2)
