# Network Retry 完整設定指南

`config/sites.yaml` 支援全域 `network` 區塊，統一控制以下網路請求行為：

- 網站憑證連線
- issuer 憑證下載
- CRL 下載
- OCSP request

## 完整範例

```yaml
check_interval_hours: 1

network:
  timeout_seconds: 10
  retry:
    enabled: true
    max_retries: 2
    backoff_strategy: exponential
    initial_delay_seconds: 0.5
    multiplier: 2.0
    max_delay_seconds: 5.0
    jitter_seconds: 0.25

sites:
  - url: "https://your.website.com"
    expected_status: "good"
    ocsp_url: "http://ocsp.website.com"
```

## 欄位說明

### network.timeout_seconds

單次請求的逾時秒數，適用於憑證連線與下載類請求。

### network.retry.enabled

是否啟用重試機制。

### network.retry.max_retries

首次請求之外的額外重試次數。

舉例：
- `max_retries: 0` 表示只嘗試 1 次
- `max_retries: 2` 表示最多嘗試 3 次（1 次首次 + 2 次重試）

### network.retry.backoff_strategy

重試延遲策略：
- `fixed`: 每次重試間隔固定
- `exponential`: 每次重試間隔依倍率遞增

### network.retry.initial_delay_seconds

第一次重試前的基礎延遲秒數。

### network.retry.multiplier

exponential 模式下每次延遲的倍率。

### network.retry.max_delay_seconds

每次重試延遲的上限秒數。

### network.retry.jitter_seconds

在 backoff 延遲上增加隨機抖動，避免多個請求同時重試造成尖峰。

## 行為補充

- CRL 若有多個發佈點，會依序 failover。
- 每個 CRL URL 都會先各自重試到上限，再切換下一個發佈點。
- Log 會記錄 retry 的 attempt 次數、retry 次數、下一次 delay 與最後錯誤。
