# site-checker

SSL/TLS 憑證監控工具，支援網站憑證檢查、CRL 驗證與 OCSP 驗證。

## 文件

- Network Retry 完整設定指南：[docs/NETWORK_RETRY.md](docs/NETWORK_RETRY.md)
- SMTP 密碼加密指南（AES-256-GCM）：[docs/ENCRYPTION.md](docs/ENCRYPTION.md)

## Network Retry（摘要）

在 `config/sites.yaml` 中可透過全域 `network` 區塊，統一控制以下網路請求的 timeout 與 retry 行為：

- 網站憑證連線
- issuer 憑證下載
- CRL 下載
- OCSP request

最小設定範例：

```yaml
network:
  timeout_seconds: 10
  retry:
    enabled: true
    max_retries: 2
    backoff_strategy: exponential
```

重點：

- `max_retries` 是首次請求之外的額外重試次數。
- `backoff_strategy` 支援 `fixed` 與 `exponential`。
- CRL 多發佈點會依序 failover，且每個 URL 會各自重試至上限。
- 詳細欄位與完整範例請見 [docs/NETWORK_RETRY.md](docs/NETWORK_RETRY.md)。

## SMTP 密碼加密（摘要）

SMTP 密碼採用 AES-256-GCM 保護。首次啟動時若偵測到明碼，程式會自動完成加密並回寫設定檔。

重點：

- 在 `config/email.yaml` 設定 `smtp_password` 為明碼後，首次啟動會自動加密為 `{AES}...`。
- 後續啟動會自動解密供執行期使用，不需手動轉換。
- 加密金鑰預設儲存在使用者目錄下的 `.site-checker/secret.key`。
- 若不使用 SMTP 認證，可將 `smtp_password` 設為空值或 `~`。
- 完整流程、金鑰遷移與異常處理請見 [docs/ENCRYPTION.md](docs/ENCRYPTION.md)。
