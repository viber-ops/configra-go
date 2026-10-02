# configra-go

**在 Go 应用里读取 Configra，不必自己初始化 TLS 和连接池。**

[产品网站](https://viber-ops.github.io/configra/) · [SDK 文档](https://viber-ops.github.io/docs/configra/go-sdk/) · [English](README.md)

读取已解析的 YAML / JSON、Vault 文件，或使用 Viper 定期刷新配置。服务端负责解析 Vault 引用，应用专注于验证和使用最终配置。

当前稳定版为 **v1.1.0**，需要 Go 1.25.13+。应用仍需处理读取错误，并在应用新快照前校验配置。

```sh
go get github.com/viber-ops/configra-go@v1.1.0
```

## 默认从环境开始

```go
client, err := configra.NewClientFromEnv()
if err != nil {
    return err
}
defer client.CloseIdleConnections()

result, err := client.ReadResolvedConfig(ctx, "production", "payment", "")
if err != nil {
    return err
}
// 解析 result.Content，不要把配置明文打印到日志。
```

部署系统提供 `CONFIGRA_URL`、`CONFIGRA_TOKEN` 或 `CONFIGRA_TOKEN_FILE`。mTLS 使用 `CONFIGRA_CLIENT_CERT` / `CONFIGRA_CLIENT_KEY`；证书与私钥合在同一个 PEM 时不需要单独设置 key 路径。内部服务器 CA 才需要 `CONFIGRA_SERVER_CA`。

SDK 负责读取证书、校验服务器、超时和连接复用，**不要求固定凭据目录**。

## 按你的习惯初始化

| 场景 | 入口 |
| --- | --- |
| 容器、已有环境变量 | `NewClientFromEnv()` |
| 本地或传统配置文件 | `NewClientFromFile("configra.yaml")` |
| 应用已有配置系统 | `NewClient(ClientOptions{...})` |

三个入口最终使用同一套选项、默认值与校验，不相互隐式覆盖。配置文件例子：

```yaml
url: https://configra-api.example.internal:9443
token_file: /run/secrets/configra-token
cert_file: /run/secrets/client.crt
key_file: /run/secrets/client.key
```

相对路径以 YAML 所在目录为基准，不随进程工作目录改变。只有内部服务器 CA 才需要 `server_ca_file`。地址、Token 不能从客户端证书推导出来；只有显式允许 Token-only 的 Token 才能不带客户端证书。

默认请求超时 30 秒，内容上限 5 MiB。高级场景可自定义 `ClientOptions`，包括 `tls.Config`；普通示例不需要了解这些实现细节。

## 热更新须知

`NewViperHandler` 支持 Load / Reload / Watch。获取或解析失败保留进程内最后可用快照；首次启动没有旧快照。OnChange 在 SDK 安装新快照后触发，回调失败不会回滚，应用应独立校验并原子替换自己的状态。

凭据文件在初始化时加载一次。变更后重建 Client，或使用高级证书回调实现在线轮换。构造 Client 不会自动启动 Watch 或其他后台循环。

更新 `TLSConfig.GetClientCertificate` 返回的证书后，可以调用 `CloseIdleConnections()` 关闭空闲连接；它不会中断进行中的请求，忙碌的 HTTP/2 连接也可能继续使用旧身份。需要立即切换身份时，应停止旧调用并换用新 Client。更换 Token 同样需要新建 Client。

[完整示例](https://github.com/viber-ops/configra-go/blob/v1.1.0/examples/basic/main.go) · [初始化、读取与 Viper 指南](https://viber-ops.github.io/docs/configra/go-sdk/)

## 许可证

项目原创代码采用 [Apache-2.0](LICENSE)，第三方组件保留各自的许可证与声明。
贡献方式见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题请通过 [SECURITY.md](SECURITY.md) 中的私密渠道报告。

## 范围写入（服务端 v1.1.0+）

部署主机保持只读凭据，operator 单独持有 `write-scoped` Token 和已注册 mTLS 证书。
管理员经 OIDC 登录及 MFA 证明后签发 writer，自动化无需持有人类 Session、CA 私钥
或 Master Key。参阅 [模型、签发与权限边界](https://github.com/viber-ops/configra/blob/feat/scoped-write-tokens/docs/scoped-write-tokens.zh-CN.md)。

```go
result, err := client.WriteConfig(ctx, "testing", "server", configra.ConfigWrite{
    RevisionWrite: configra.RevisionWrite{OperationID: "upload-server-001", ExpectedRevision: 0},
    Name: "server.yaml", Format: "yaml", Content: "port: 8080\n",
})
```

新内容用新 OperationID，相同请求重试复用原 ID。创建时 ExpectedRevision=0，更新时
使用当前版本。403 表示范围拒绝，401 表示凭据失效/缺失，409 表示版本或 OperationID
冲突；`APIError` 只含安全码与 Request ID，不自动记录任何值或凭据导出。

| 方法 | 用途 |
| --- | --- |
| `WriteConfig`、`ReadRawConfig` | 写入版本，读取当前原文/版本 |
| `WriteVaultItem`、`ReadVaultItem` | 替换/读取单环境完整 item 值 |
| `WriteVaultField`、`WriteFile` | 新建/更新 Text/Secret/File 字段 |
| `DeleteVaultField`、`DeleteVaultItem` | 移除共享字段或归档 item，保留历史 |
| `IssueDeploymentCredential`、`RevokeDeploymentCredential` | 原子签发/吊销只读 Token 与绑定证书 |

共享字段结构操作必须拥有全部绑定环境权限。File 以 JSON/base64 上传，每个最长
5 MiB、每个 Vault 快照最长 10 MiB。部署凭据继承白名单，期限不超过 writer/CA；
writer 吊销会级联吊销其部署 pair。首次签发才返回 Token 与 base64 ZIP，重试只返回
元数据。导出通过私密渠道分发，Token/私钥使用 0600。

[operator 示例](examples/operator/main.go) 在写入前读取当前版本，上传 server YAML
和完整的一组密钥文件，之后保存新的只读部署 pair。17 个参数对应 `file_01` 至
`file_17`；文件参数需保持固定顺序。

```sh
export CONFIGRA_URL=https://configra-api.example.internal:9443
export CONFIGRA_TOKEN_FILE=/run/secrets/operator-token
export CONFIGRA_CLIENT_CERT=/run/secrets/operator.crt
export CONFIGRA_CLIENT_KEY=/run/secrets/operator.key
export CONFIGRA_SERVER_CA=/run/secrets/server-ca.crt
export CONFIGRA_DEPLOYMENT_CA_ID=YOUR_PUBLIC_MANAGED_CA_ID
go run ./examples/operator -environment testing -namespace deployment \
  -authority "$CONFIGRA_DEPLOYMENT_CA_ID" -config server.yaml \
  -output deployment-identity secrets/*.key
```

示例使用 Config key `server`、Vault item `deployment/secrets`，签发 24 小时的主机
凭据（writer 至少剩余该期限），输出目录必须不存在。`token`、`client.zip` 为 0600。
请在私密目录解压；其中 ca.crt 是客户端签发信任根，不一定是 HTTPS 服务端 CA。
旧读取方法和 Viper Handler 兼容旧服务端。Configra 仓库的 `make test-integration`
会在真实 MySQL 8.0.22/NATS/ClickHouse + HTTPS/mTLS 上执行此示例。
