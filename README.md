# snowland-jwt

#### 介绍
国密版本jwt

#### 软件架构
基于 [PyJWT](https://pypi.org/project/PyJWT/) 的 `jwt.algorithms.Algorithm` 扩展点，
用 SM2（GB/T 0003，完整 `ZA||M` 预哈希，与标准国密工具链互认）实现非对称签名，
用 HMAC-SM3 实现对称签名，从而替代 RSA/ECDSA/HMAC-SHA 系列，满足国密场景的 token
生成与鉴权需求。

**底层密码学是可插拔的可选后端**（库本身不硬依赖任一）：
- `pysmx`（包名 `snowland-smx`）：SM2 类 API，签名采用原始 `r || s` 编码；
- `gmssl-pyx`：GmSSL 绑定，签名采用 ASN.1 DER `rs` 编码。

两者都实现相同的 GB/T 0003 `ZA||M` 预哈希（默认签名者 ID `1234567812345678`），
因此对同一 `IDA`、同一后端可互认。注意两个后端产出的**签名字节编码不同**
（raw vs DER），故 token 只能由生成它的同一后端验签；而 HMAC-SM3 基于标准 SM3
摘要计算，与所选后端无关、可跨后端互认。

产出的仍是标准 JWT（`header.payload.signature`），仅 `alg` 为国密算法名，
可兼容现有 JWT 工具链。

支持的算法：

| alg 名称 | 类型 | 替代对象 |
|----------|------|----------|
| `SM2` | 非对称（SM2 + SM3 签名，完整 `ZA||M` 预哈希） | ES256 / RS256 |
| `HS256-SM3` | 对称（HMAC + SM3） | HS256 |

#### 安装教程

基础依赖只含 `pyjwt` 与 `cryptography`；国密后端为可选，按需要安装其一：

```bash
# 使用 snowland-smx（pysmx）后端
pip install "snowland-jwt[smx]"      # snowland-smx>=1.1.0

# 或使用 gmssl-pyx 后端
pip install "snowland-jwt[gmssl]"    # gmssl-pyx>=2.1.0
```

不安装任何后端时，库可正常导入；但首次签发/验签会抛出 `BackendNotAvailable`，
提示安装上述后端之一。未指定后端时按 `gmssl-pyx` → `pysmx` 的顺序自动选择。

#### 使用说明

```python
import snowland_jwt as jwt

# 生成 SM2 密钥对（私钥 32 字节 / 16 进制 64 字符，公钥 64 字节 / 128 字符）
private_key, public_key = jwt.generate_key()

# 签发（默认算法为 SM2）
token = jwt.encode({"sub": "user-001"}, private_key, algorithm=jwt.SM2)

# 验签
payload = jwt.decode(token, public_key, algorithms=[jwt.SM2])
```

对称算法示例：

```python
secret = "guomi-shared-secret-key-0123456789abcdef"
token = jwt.encode({"iss": "snowland"}, secret, algorithm=jwt.HS256_SM3)
payload = jwt.decode(token, secret, algorithms=[jwt.HS256_SM3])
```

指定后端（双方约定使用某一后端，或约定非默认 `IDA`）：

```python
# 显式绑定 gmssl-pyx 后端，并使用默认 IDA
jwt.register_sm2(jwt.DEFAULT_SM2_UID, backend="gmssl_pyx")

# 约定自定义 IDA（双方必须一致；IDA 本身不入 token）
jwt.register_sm2(b"custom-ida-2026", alg_name="SM2-MY", backend="gmssl_pyx")
```

密钥格式说明（`SM2`）：
- 原始 `bytes`：32 字节私钥（会自动按 SM2 曲线派生公钥 `d·G`），或 64 字节（`x||y`）/ 65 字节（`0x04||x||y`）公钥；
- hex 字符串：同上长度的十六进制；
- PEM（`-----BEGIN ...`）：经 `cryptography` 解析；
- JWK（`dict` / JSON，`kty=EC`、`crv=SM2`）。

导入本库后，标准 `import jwt; jwt.encode(..., algorithm="SM2")` 亦可工作（已注册到全局算法表）。

#### API 文档

##### v0.1
完整函数级参考（每个函数的入参、出参、功能与异常）见 [API.md](docs/api/v0_1_0/API.md)。
