# SMTP 密碼加密指南

本程式對 SMTP 密碼採用 AES-256-GCM 加密，首次啟動時自動進行加密與保護。

## 密碼設定流程

### 首次設定（明碼→密文）

1. 編輯 `config/email.yaml`，填入 SMTP 密碼（明碼）：
   ```yaml
   smtp_password: your_actual_password
   ```

2. 啟動程式，會自動執行以下步驟：
   - 產生 AES-256 金鑰，存放在 `~/.site-checker/secret.key`
   - 加密密碼，存放為 `{AES}...` 格式
   - 更新 `config/email.yaml`，密碼變成密文

3. 後續啟動時，程式自動解密密文供執行期使用，無需手動操作

### 密文已存在

若 `config/email.yaml` 中已有 `{AES}...` 密文，程式將自動解密使用，不再重複回寫。

### 跳過認證

若不需要 SMTP 認證，留空或設為 null：
```yaml
smtp_password: ~  # 或 smtp_password:（空值）
```

## 金鑰管理

### 金鑰位置

金鑰自動存儲在使用者 home 目錄：
- **Windows**: `C:\Users\<username>\.site-checker\secret.key`
- **Linux/macOS**: `/home/<username>/.site-checker/secret.key` 或 `/Users/<username>/.site-checker/secret.key`

### 金鑰建立

每個使用者首次啟動時，程式自動產生 32-byte 隨機金鑰並儲存到上述位置。

### 跨機器遷移

若需在另一台機器上執行程式，有兩個方案：

**方案 A：複製金鑰（推薦，密文保持有效）**
1. 從舊機器複製 `~/.site-checker/secret.key`
2. 放到新機器相同位置
3. 啟動程式，密文會正常解密

**方案 B：重新設定密碼**
1. 刪除新機器上的 `~/.site-checker/secret.key`（若存在）
2. 編輯 `config/email.yaml`，將密碼改為新金鑰無法解密的任意明碼
3. 啟動程式，會自動以新金鑰重新加密

## 異常處理

### 情況 1：金鑰遺失或損毀

**症狀**：無法解密，程式啟動失敗

**解決方案**：

- A. 若有舊金鑰備份，複製至 `~/.site-checker/secret.key` 後重啟
- B. 若無備份，編輯 `config/email.yaml`，將 `smtp_password` 改為任意非空字串（不含 `{AES}` 前綴），重啟程式會自動以新金鑰重新加密

### 情況 2：密文已損毀

**症狀**：無法解密，Error: 解密失敗

**解決方案**：
1. 編輯 `config/email.yaml`，將 `smtp_password` 改為新的明碼
2. 重啟程式，新密碼會被自動加密並儲存

### 情況 3：不小心刪除 `config/email.yaml`

備份檔預料不會自動建立，但可以：
1. 從 `config/email.yaml.sample` 複製一份作為 `config/email.yaml`
2. 填入新的 SMTP 密碼（明碼）
3. 重啟程式，自動加密

## 密文格式

密文採用標準格式便於未來升級：

```
{AES}[Base64編碼的 payload]
```

Payload 內部結構：
- 版本位元組（1 byte）：當前值 0x01，預留升級空間
- Nonce（12 bytes）：GCM 模式隨機初始化向量  
- 加密資料 + 完整性標籤（N bytes）：AES-256-GCM 的輸出

同一明碼加密多次會產生不同密文（因為 nonce 隨機），但解密結果一致。

## 安全性說明

- 密碼在記憶體中僅存在於執行期，不持久化明碼
- 金鑰文件權限設為 0600（Unix/Linux）或依賴 Windows ACL
- 密文儲存在 YAML 檔案中，與其他設定並存
- 若 `config/email.yaml` 與 `~/.site-checker/secret.key` 都被竊取，攻擊者可解密密碼

## 常見問題

### Q: 為何總是要有金鑰？

A: 金鑰用於解密儲存的密文。若不使用密碼認證（`smtp_password: ~`），則不需要。

### Q: 能改密碼嗎？

A: 是的。編輯 `config/email.yaml`，改成新密碼（明碼）即可，下次啟動就會自動以新值重新加密。

### Q: 能導出明碼密碼嗎？

A: 只有程式執行期間會在記憶體中持有明碼，不提供導出功能。若需取得舊密碼，只能重設。
