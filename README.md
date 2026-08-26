<h1 align="center">
cf-Pages-doh
</h1>

一个带有伪装可以部署在cloudflare Pages的DNS over HTTPS服务

### 有什么用

因为国内运营商和防火墙大量封锁国外doh等加密dns服务 所以如果你想使用国外doh服务就需要自行部署
以及cloudflare Pages默认域名.pages.dev还未被封锁所以不需要自定义域名即可使用
### 上传

注册一个Cloudflare账号 创建一个Pages 下载_worker.js和你自定义的index.html一起上传到Pages即可

### 自定义

_worker.js默认doh请求路径是/dns-query 可在_worker.js内自行修改 默认上游dns为cloudflare的doh服务器

### 测试
打开cmd输入
```bash
curl -i -H "accept: application/dns-json" "https://你的域名/自定义后缀?name=example.com&type=A"
```
### ...

部署在cloudflare Pages如果访问index.html等静态资源不消耗每日请求数 访问doh服务将会消耗每日请求数
免费套餐每日请求数为10万，足够大多数个人使用
