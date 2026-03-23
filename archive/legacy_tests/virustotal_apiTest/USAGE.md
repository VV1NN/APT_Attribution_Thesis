# VirusTotal API v3 高階研究資料抓取器 — 使用說明

本文件說明如何使用 `vt_test.py` 進行 IoC 關聯資料抓取與輸出。

## 1. 環境與相依套件（使用 uv）

此專案已提供 `pyproject.toml` 與 `.python-version`，建議用 uv 管理 Python 版本與依賴。

1) 安裝 uv（尚未安裝時）

```
curl -LsSf https://astral.sh/uv/install.sh | sh
```

2) 同步 Python 版本與依賴

```
uv sync
```

3) 以 uv 執行腳本

```
uv run python vt_test.py --input iocs.txt --output vt_output --env .env
```

> 若你不使用 uv，也可自行建立 venv 並安裝 requests。

## 2. API Key 設定

請在同一資料夾建立或確認已有 `.env` 檔，內容格式如下：

```
VT_API_KEY=你的_VirusTotal_API_Key
```

也可使用 `VIRUSTOTAL_API_KEY` 作為備援環境變數名稱。

## 3. IoC 輸入檔格式

輸入為純文字檔（UTF-8），每行一個 IoC：

- 檔案雜湊（MD5 / SHA1 / SHA256）
- IP 位址（IPv4 / IPv6）
- 網域名稱（Domain）

範例：

```
44d88612fea8a8f36de82e1278abb02f
8.8.8.8
example.com
```

## 4. 執行方式

從 `Virustotal_apiTest` 目錄執行（uv）：

```
uv run python vt_test.py --input iocs.txt --output vt_output --env .env
```

參數說明：

- `--input`：IoC 清單檔案（必填）
- `--output`：輸出目錄（預設：`vt_output`）
- `--env`：API Key 的 `.env` 路徑（預設：`.env`）

## 5. 輸出結構

每筆 IoC 會輸出一個 JSON 檔案（檔名已安全化），範例結構：

```
{
  "ioc": "example.com",
  "ioc_type": "domain",
  "nodes": [
    {"id": "<related_id>", "type": "<related_type>"}
  ],
  "edges": [
    {
      "source": "example.com",
      "source_type": "domain",
      "target": "<related_id>",
      "target_type": "<related_type>",
      "relationship": "resolutions"
    }
  ],
  "ttp_tags": ["T1059", "T1027"]
}
```

## 6. 會抓取的關聯類型

- File Hash
  - `contacted_ips`
  - `contacted_domains`
  - `dropped_files`
  - `execution_parents`

- IP / Domain
  - `communicating_files`
  - `downloaded_files`
  - `resolutions`

## 7. 錯誤與速率限制處理

- 429 (Too Many Requests)：會依 `Retry-After` 或退避策略自動重試
- 401 (Invalid API Key)：記錄錯誤但不中斷
- 404 (Not Found)：記錄警告但不中斷

## 8. 日誌

會在輸出資料夾內產生 `vt_fetcher.log`，紀錄處理流程與錯誤訊息。
