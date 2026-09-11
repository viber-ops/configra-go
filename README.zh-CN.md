# configra-go

**在 Go 应用里读取 Configra，不必自己初始化 TLS 和连接池。**

[产品网站](https://viber-ops.github.io/configra/) · [SDK 文档](https://viber-ops.github.io/docs/configra/go-sdk/) · [English](README.md)

读取已解析的 YAML / JSON、Vault 文件，或使用 Viper 定期刷新配置。服务端负责解析 Vault 引用，应用专注于验证和使用最终配置。

当前为 **v0.1.0-rc.1 预发布**，下面的初始化方式对应此标签；需要 Go 1.25.13+。

```sh
go get github.com/viber-ops/configra-go@v0.1.0-rc.1
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

[完整示例](https://github.com/viber-ops/configra-go/blob/v0.1.0-rc.1/examples/basic/main.go) · [初始化、读取与 Viper 指南](https://viber-ops.github.io/docs/configra/go-sdk/)

## 许可证

项目原创代码采用 [Apache-2.0](LICENSE)，第三方组件保留各自的许可证与声明。
贡献方式见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题请通过 [SECURITY.md](SECURITY.md) 中的私密渠道报告。
