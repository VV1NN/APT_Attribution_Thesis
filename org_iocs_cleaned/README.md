# IoC 清理說明

本資料夾包含 `org_iocs` 清理後的結果，目標是降低報告引用連結造成的圖譜汙染，保留可用的 IoC 並移除雜訊。

## 清理輸入與輸出

- 輸入：`org_iocs/**/iocs.json`（每筆為 `{ "type", "value", "sources" }`）
- 輸出：`org_iocs_cleaned/**/iocs.json`（保留原始目錄結構）

## 清理規則摘要

1. 型別篩選（僅保留）
   - `ipv4`, `domain`, `url`, `md5`, `sha1`, `sha256`

2. 正規化與去重
   - `value` 轉為小寫（URL/Domain/Hash/IP）
   - 同一組織內若 `type + value` 相同，合併 `sources`
   - URL 會解析出 `domain` 欄位供後續圖譜使用

3. 黑名單過濾（eTLD+1）
   - 對 `domain` 與 `url` 取 eTLD+1
   - 若 eTLD+1 落在黑名單則移除

4. 私有 IP 過濾
   - 僅過濾 RFC1918 私有網段與 Loopback

## 黑名單與例外

eTLD+1 黑名單（雜訊網站）：

- `fireeye.com`
- `google.com`
- `microsoft.com`
- `bbc.com`
- `cnn.com`
- `nytimes.com`
- `scmp.com`
- `ejinsight.com`
- `github.com`
- `twitter.com`
- `wikipedia.org`

動態 DNS 白名單（例外保留）：

- `serveftp.com`

## 實作位置

- 清理腳本：`ioc_extract/clean_org_iocs.py`
- 規則與工具：`ioc_extract/utils/filters.py`

## 執行方式

在專案根目錄執行：

```
python ioc_extract/clean_org_iocs.py
```

執行後會產生 `org_iocs_cleaned/`，且不會覆寫原始資料。
