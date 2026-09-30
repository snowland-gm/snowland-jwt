# snowland-jwt 性能基准 (Benchmark)

- 环境: Python 3.13.13, pysmx 1.1.0, gmssl-pyx 2.1.0
- 测量: 每配置 warm-up 5 次 + 200 次取均值

## HMAC-SM3 encode

| Backend | ops/s | ms/op |
|---|---|---|
| default | 19032.0 | 0.053 |

## HMAC-SM3 sign

| Backend | ops/s | ms/op |
|---|---|---|
| pysmx | 63125.3 | 0.016 |
| gmssl_pyx | 46710.4 | 0.021 |

## SM2 encode

| Backend | ops/s | ms/op |
|---|---|---|
| pysmx | 47.8 | 20.906 |
| gmssl_pyx | 23.7 | 42.274 |

## SM2 verify

| Backend | ops/s | ms/op |
|---|---|---|
| pysmx | 30.6 | 32.679 |
| gmssl_pyx | 23.0 | 43.549 |
