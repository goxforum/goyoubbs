# Go-XForum
[![Go Report Card](https://goreportcard.com/badge/github.com/goxforum/xforum)](https://goreportcard.com/report/github.com/goxforum/xforum)

GoXForum 基于youBBS做了若干调整

```
go get github.com/goxforum/xforum/cmd/xforum/...
```

## 计划支持功能
- [x] 云存储上传前缀支持
- [x] 将静态文件嵌入go二进制包,安装不需要下载静态资源
- [x] LDAP登录支持
- [ ] Docker部署
- [ ] InfluxDB metrics收集



## 技术改动
- [x] 使用dep管理依赖包
- [x] 代码结构调整
- [ ] 后端存储支持MongoDB

