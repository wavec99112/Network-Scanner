
# Network Scanner

Network Scanner是一个用Python编写的网络扫描工具，旨在帮助用户在Kali Linux上执行网络渗透测试。
本工具仅供合法的网络安全研究、教学和评估用途。请勿在未经授权的系统上使用。任何非法使用本工具的行为，责任自负。

## 特性

- 自动检测局域网范围
- 扫描局域网内的所有主机
- 检测开放端口和服务
- 分析端口信息并判断操作系统和设备类型
- 生成扫描报告（PDF和HTML格式）
- 详细日志记录
## 克隆仓库
```
git clone https://github.com/wavec99112/Network-Scanner.git
cd network-scanner
```
## 安装

### 前提条件

- 确保你的系统上已经安装了Python 3.x。
- 需要安装的Python依赖包：

```
pip install -r requirements.txt
```
### requirements.txt文件内容如下：
```
nmap
fpdf
tqdm
requests
```

## 运行工具
### 在命令行中运行以下命令来启动工具：
```
python ip.py
```
## 使用说明
### 扫描局域网
启动工具后，会提示是否开始扫描，输入y开始扫描。
复制代码
是否开始扫描？(y/n): y
工具会自动检测局域网范围，并开始扫描所有主机。
扫描完成后，结果会保存到以下文件：
```
scan_results.csv: CSV格式的扫描结果
scan_log.txt: 详细的日志记录
scan_report.pdf: PDF格式的扫描报告
scan_report.html: HTML格式的扫描报告
```
## 配置
### 如果需要手动配置局域网范围，可以修改代码中的默认值：
```
python
复制代码
def get_local_network_range():
    return '192.168.1.0/24'  # 修改为你的局域网范围
```
贡献
如果你想要贡献代码或报告问题，欢迎提交Pull Request或Issue：
```
Fork 本仓库
创建新的分支 (git checkout -b feature-branch)
提交你的修改 (git commit -am 'Add new feature')
推送到分支 (git push origin feature-branch)
创建一个新的 Pull Request
```
## 许可：
```
版权所有 (c) 2024 WAVE-C9
特此免费授予获得本软件及相关文档文件（“软件”）副本的任何人无限制地处理本软件的权限，包括但不限于使用、
复制、修改、合并、发布、分发、再许可和或销售软件副本的权利，以及允许向其提供本软件的人这样做，但须符合
以下条件：本工具仅供合法的网络安全研究、教学和评估用途。请勿在未经授权的系统上使用。
本软件按“原样”提供，不提供任何明示或暗示的担保，包括但不限于对适销性、特定用途适用性和非侵权的担保。
在任何情况下，作者或版权持有人均不对因本软件或使用本软件或其他交易中的使用或其他交易而产生的任何索赔、
损害或其他责任负责，无论是在合同诉讼、侵权行为或其他方面。

```
## 维护者：Wave-C9
