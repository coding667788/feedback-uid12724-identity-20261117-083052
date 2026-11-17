"""本地服务间令牌交换器（HMAC-SHA256 自定义令牌封装）。

模块划分：
- errors:    统一错误码与异常
- encoding:  base64url 严格编解码、规范化 JSON、重复键检测
- token:     HST1 令牌的构造、解码、签名与结构化校验
- registry:  受信租户/服务/密钥/交换边注册表
- store:     SQLite 交换去重、祖先闭包与撤销存储
- service:   铸造、在线验证、交换、撤销的核心业务
- mock_services: 本机模拟服务（无网络）
- cli:       cases.json 驱动的命令行入口
"""

__version__ = "1.0.0"
