from flask import Flask, request, jsonify
import subprocess
import logging

app = Flask(__name__)

# 設定基本的日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/')
def index():
    """
    歡迎頁面，告知使用者這是一個受 WAF 保護的目標應用。
    """
    return "<h1>Welcome to the Target Application</h1><p>This application is protected by the WAF. Try your attacks!</p>"

@app.route('/healthz')
def healthz():
    """
    應用程式自身的健康檢查端點。
    """
    return jsonify({"status": "ok"})

@app.route('/search', methods=['GET'])
def search():
    """
    一個模擬的搜尋功能，容易受到 XSS 或 SQLi 攻擊。
    注意：這裡僅為模擬，並未實際連接資料庫。
    """
    query = request.args.get('query', '')
    logging.info(f"Received search query: {query}")
    # 在真實應用中，這裡可能會有資料庫查詢
    # 為了靶場目的，我們直接回顯查詢參數，使其容易觸發 XSS
    return f"<h2>Search Results for: {query}</h2><p>No results found.</p>"

@app.route('/exec', methods=['POST'])
def execute_command():
    """
    一個極度不安全的端點，用於模擬命令注入漏洞。
    CRTO 的目標之一就是利用這個端點執行指令。
    """
    data = request.get_json()
    cmd = data.get('cmd', '')

    if not cmd:
        return jsonify({"error": "No command provided"}), 400

    logging.info(f"Executing command: {cmd}")
    try:
        # 警告：這是一個巨大的安全漏洞，僅用於受控的靶場環境！
        # 使用 shell=True 是為了模擬真實世界的漏洞場景
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        return jsonify({"output": result})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Command failed", "output": e.output}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # 監聽 0.0.0.0 以便 Docker 容器可以訪問
    app.run(host='0.0.0.0', port=5000)

