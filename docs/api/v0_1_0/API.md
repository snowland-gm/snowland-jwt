# snowland-jwt API 文档

> English: [API.en.md](API.en.md)

本文件逐一说明 `snowland_jwt` 公开函数的**入参、出参、功能与异常**。

约定：
- 密钥输入 `key` 支持多种形式：原始 `bytes`、十六进制 `str`、PEM 文本（`-----BEGIN ...`）、
  JWK（`dict` 或 JSON `str`，`kty=EC`、`crv=SM2`）、以及后端原生密钥对象。
- 所有加密运算委托给**可插拔后端**（`pysmx` / `gmssl_pyx`），后端为可选依赖，未安装时首个加密调用抛
  `BackendNotAvailable`。
- 算法名常量：`SM2`（`"SM2"`）、`HS256_SM3`（`"HS256-SM3"`）。

---

## 1. 包级函数（`snowland_jwt`）

### 1.1 `encode(payload, key, algorithm=SM2, headers=None, json_encoder=None, sort_headers=True)`

生成 JWT 字符串。

| 参数 | 类型 | 说明 |
|---|---|---|
| `payload` | `dict` | 负载（claims），会被 JSON 序列化。 |
| `key` | `bytes` / `str` / 密钥对象 | 签名密钥。SM2 用私钥；`HS256-SM3` 用共享密钥。 |
| `algorithm` | `str` | 算法名，默认 `SM2`。可选 `HS256_SM3` 或经 `register_sm2` 注册的变体。 |
| `headers` | `dict` / `None` | 附加到 JWT 头的自定义字段（如 `kid`）。 |
| `json_encoder` | `json.JSONEncoder` / `None` | 自定义 JSON 编码器。 |
| `sort_headers` | `bool` | 是否对头部字段排序，默认 `True`。 |

- **返回**：`str` —— 形如 `header.payload.signature` 的 JWT。
- **异常**：`BackendNotAvailable`（后端未装）、`InvalidKeyError`（密钥格式不支持）、`InvalidAlgorithmError`（算法未注册）。

---

### 1.2 `decode(token, key, algorithms=None, options=None, **kwargs)`

校验并解码 JWT，返回负载。

| 参数 | 类型 | 说明 |
|---|---|---|
| `token` | `str` / `bytes` | JWT 字符串。 |
| `key` | 同 `encode` | 验签密钥。SM2 用公钥；`HS256-SM3` 用共享密钥。 |
| `algorithms` | `list` / `None` | 允许的算法名列表。**默认 `[SM2, HS256_SM3]`**。传 `None` 不会拒绝全部，而是回退默认列表。 |
| `options` | `dict` / `None` | 校验选项（同 PyJWT：`verify_signature`、`verify_exp`、…）。 |
| `**kwargs` | — | 透传给 PyJWT，如 `audience`、`issuer`、`leeway`。 |

- **返回**：`dict` —— 解码后的负载。
- **异常**：`InvalidSignatureError`（签名不符）、`ExpiredSignatureError`（过期）、`InvalidTokenError`（格式/校验失败）等；`BackendNotAvailable`、`InvalidKeyError`。

---

### 1.3 `decode_complete(token, key, algorithms=None, options=None, **kwargs)`

同 `decode`，但返回完整结构。

- **参数**：同 `decode`。
- **返回**：`dict` —— 形如 `{"header": ..., "payload": ..., "signature": ...}`。
- **异常**：同 `decode`。

---

### 1.4 `generate_key()`

用默认后端生成 SM2 密钥对。

- **入参**：无。
- **返回**：`tuple[str, str]` —— `(private_key_hex, public_key_hex)`。
  - 私钥：32 字节 / 64 个十六进制字符。
  - 公钥：64 字节 / 128 个十六进制字符，格式为 `x || y`。
- **异常**：`BackendNotAvailable`（后端未装）。

---

### 1.5 `register_sm2(uid=DEFAULT_SM2_UID, alg_name=None, backend=None)`

注册一个绑定特定 `IDA`（用户标识）和/或后端的 SM2 算法变体。

双方需约定相同的 `IDA`；相同 `IDA` 且相同后端时才可互验。不同 `IDA` 之间不可互验。

| 参数 | 类型 | 说明 |
|---|---|---|
| `uid` | `str` / `bytes` | 用户标识 `IDA`，用于 GB/T 0003 的 `ZA || M` 预哈希。 |
| `alg_name` | `str` / `None` | 注册的算法名。省略时自动派生为 `"SM2-" + uid前8字节hex`，如 `"SM2-31323334"`。 |
| `backend` | `str` / `None` | 后端名 `"pysmx"` / `"gmssl_pyx"`，`None` 表示自动选择。 |

- **返回**：`str` —— 实际注册的算法名（供 `encode`/`decode` 的 `algorithm=` 使用）。
- **异常**：`BackendNotAvailable`（指定后端未装）。
- **说明**：若 `alg_name` 已注册则直接返回，不会重复注册。

---

### 1.6 `register_hmac_sm3(alg_name=HS256_SM3, backend=None)`

注册一个绑定特定后端的 HMAC-SM3 算法变体。

| 参数 | 类型 | 说明 |
|---|---|---|
| `alg_name` | `str` | 注册的算法名，默认 `"HS256-SM3"`。 |
| `backend` | `str` / `None` | 后端名；HMAC-SM3 的 SM3 取自后端 `sm3_hash`，跨后端字节一致，此参数仅用于接口对称。 |

- **返回**：`str` —— 注册的算法名。
- **异常**：`BackendNotAvailable`（后端未装）。

---

### 1.7 `get_crypto_backend(name=None)`

获取一个已初始化的加密后端实例。由 `snowland_jwt.backends` 提供。

| 参数 | 类型 | 说明 |
|---|---|---|
| `name` | `str` / `None` | 后端名。省略时按 `_DEFAULT_PROBE_ORDER`（`("gmssl_pyx", "pysmx")`）取第一个可用后端。 |

- **返回**：`CryptoBackend` 实例（具体为 `PysmxBackend` 或 `GmsslPyxBackend`）。
- **异常**：`BackendNotAvailable`（无可用后端，或 `name` 未知/未安装）。

---

## 2. 算法类（`snowland_jwt.algorithms`）

### 2.1 `SM2Algorithm(backend=None, uid=DEFAULT_SM2_UID)`

SM2 签名算法（GM/T 0003，完整 `ZA || M` 预哈希）。

| 参数 | 类型 | 说明 |
|---|---|---|
| `backend` | `str` / `None` | 后端名或自动选择。 |
| `uid` | `str` / `bytes` | 用户标识 `IDA`，默认 `b"1234567812345678"`。 |

**方法**

| 方法 | 入参 | 出参 | 功能 / 异常 |
|---|---|---|---|
| `prepare_key(key)` | 任意密钥形式 | `SM2Key` | 归一化为后端中立的 `SM2Key`。不支持的格式抛 `InvalidKeyError`。 |
| `sign(msg, key)` | `msg: bytes`、`key: SM2Key`（含私钥） | `bytes` | 用后端对 `msg` 做 SM2 签名（含 `ZA || M` 预哈希）。无私钥抛 `InvalidKeyError`。 |
| `verify(msg, key, sig)` | `msg: bytes`、`key: SM2Key`（含公钥）、`sig: bytes` | `bool` | 验签。无公钥抛 `InvalidKeyError`。 |
| `to_jwk(key_obj, as_dict=False)` | `SM2Key`、`as_dict: bool` | `dict` 或 JSON `str` | 导出为 `kty=EC, crv=SM2` 的 JWK。非 `SM2Key` 抛 `InvalidKeyError`。 |
| `from_jwk(jwk)` | `dict`/JSON `str` | `SM2Key` | 从 JWK 导入。非 `EC/SM2` 抛 `InvalidKeyError`。 |
| `_prepare_raw(key_bytes)` | `bytes` | `SM2Key` | 解析原始字节：32 字节私钥自动派生公钥 `d·G`；64 字节或 `0x04`+64 字节公钥。长度不符抛 `InvalidKeyError`。 |
| `_prepare_pem(key_bytes)` | `bytes` | `SM2Key` | 解析 PEM 私钥/公钥。不支持抛 `InvalidKeyError`。 |
| `_derive_public_point(d)` | `int`（私钥标量） | `(x, y)` | 在 SM2 曲线上计算 `d·G`（标准点乘，后端无关）。 |
| `_crypto()` | 无 | `CryptoBackend` | 惰性获取后端实例（按需初始化）。 |

### 2.2 `HMACSM3Algorithm(backend=None)`

HMAC-SM3 对称算法（RFC 2104，哈希用标准 SM3）。

| 参数 | 类型 | 说明 |
|---|---|---|
| `backend` | `str` / `None` | 后端名；SM3 取自后端 `sm3_hash`，跨后端一致。 |

**方法**

| 方法 | 入参 | 出参 | 功能 / 异常 |
|---|---|---|---|
| `prepare_key(key)` | 任意 | `bytes` | 归一化为字节密钥；`dict` 走 `from_jwk`。 |
| `sign(msg, key)` | `msg: bytes`、`key: bytes` | `bytes` | 计算 HMAC-SM3 签名。 |
| `verify(msg, key, sig)` | 同 `sign` + `sig` | `bool` | 恒定时间比对验签。 |
| `to_jwk(key_obj, as_dict=False)` | `bytes`/`str`、`bool` | `dict`/JSON `str` | 导出为 `kty=oct` JWK。 |
| `from_jwk(jwk)` | `dict`/JSON `str` | `bytes` | 从 JWK 导入共享密钥。非 `oct` 抛 `InvalidKeyError`。 |
| `_hmac_sm3(key, data, hash_func)` | `key: bytes`、`data: bytes`、`hash_func` | `bytes` | 标准 RFC 2104 HMAC 实现（块长 64）。 |
| `_crypto()` | 无 | `CryptoBackend` | 惰性获取后端实例。 |

### 2.3 `SM2Key`（`dataclass`）

后端中立的 SM2 密钥容器。

| 字段 | 类型 | 说明 |
|---|---|---|
| `public_key` | `bytes` | 64 字节公钥点 `x || y`（必填）。 |
| `private_key` | `Optional[bytes]` | 32 字节私钥标量 `d`（仅私钥时有值）。 |

---

## 3. 后端类（`snowland_jwt.backends`）

### 3.1 `CryptoBackend`（抽象基类）

所有后端实现的统一接口；密钥一律用原始字节交换（私钥 32 字节、公钥 64 字节）。

| 方法 | 入参 | 出参 | 功能 |
|---|---|---|---|
| `sm3_hash(data)` | `bytes` | `bytes` | 标准 SM3 摘要（32 字节）。 |
| `sm2_generate_keypair()` | 无 | `(priv: bytes, pub: bytes)` | 生成 SM2 密钥对。 |
| `sm2_sign(msg, private_key, public_key, uid)` | `bytes` ×3 + `uid` | `bytes` | SM2 签名（含 `ZA || M`）。 |
| `sm2_verify(msg, signature, public_key, uid)` | `bytes` ×3 + `uid` | `bool` | SM2 验签。 |

### 3.2 `PysmxBackend` / `GmsslPyxBackend`

`CryptoBackend` 的两个具体实现。

- `PysmxBackend`（`name="pysmx"`）：基于 `snowland-smx`（pysmx）。SM2 用类式 API，签名编码为 raw `r || s`；SM3 取自 `pysmx.crypto.hashlib`。
- `GmsslPyxBackend`（`name="gmssl_pyx"`）：基于 `gmssl-pyx`。SM2 签名编码为 ASN.1 DER `rs`；SM3 取自 `gmssl_pyx.sm3_hash`。
- 两者 SM2 签名**字节编码不同**，故只能由同一后端互验；HMAC-SM3 因 SM3 为标准摘要，跨后端一致。

### 3.3 `BackendNotAvailable`（异常）

继承 `jwt.exceptions.InvalidKeyError`。当无可用后端（或指定后端未安装）时由 `get_crypto_backend` 抛出。

---

## 4. 常量

| 名称 | 值 | 说明 |
|---|---|---|
| `SM2` | `"SM2"` | SM2 算法名。 |
| `HS256_SM3` | `"HS256-SM3"` | HMAC-SM3 算法名。 |
| `DEFAULT_SM2_UID` | `b"1234567812345678"` | GB/T 0003 示例 `IDA`，SM2 预哈希默认用户标识。 |
| `__version__` | `"0.1.0"` | 包版本。 |

---

## 5. 异常一览

所有异常均重新导出自 `jwt.exceptions`，可直接 `from snowland_jwt import InvalidSignatureError` 等：
`DecodeError`、`ExpiredSignatureError`、`ImmatureSignatureError`、`InvalidAudienceError`、
`InvalidIssuedAtError`、`InvalidIssuerError`、`InvalidKeyError`、`InvalidSignatureError`、
`InvalidTokenError`、`InvalidAlgorithmError`、`MissingRequiredClaimError`、`PyJWKError`、
`PyJWKSetError`、`InvalidSubjectError`、`InvalidJTIError`，以及本库特有的 `BackendNotAvailable`。
