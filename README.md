# Network Scanner

Network Scanner是一个用Python编写的网络扫描工具，旨在帮助用户在Kali Linux上执行网络渗透测试。

## 特性

- 自动检测局域网范围
- 扫描局域网内的所有主机
- 检测开放端口和服务
- 分析端口信息并判断操作系统和设备类型
- 生成扫描报告（PDF和HTML格式）
- 详细日志记录

## 安装

### 前提条件

- 确保你的系统上已经安装了Python 3.x。
- 需要安装的Python依赖包：

```sh
pip install -r requirements.txt
requirements.txt文件内容如下：

text
复制代码
nmap
fpdf
tqdm
requests
克隆仓库
sh
复制代码
git clone https://github.com/your-username/network-scanner.git
cd network-scanner
运行工具
在命令行中运行以下命令来启动工具：

sh
复制代码
python ip.py
使用说明
扫描局域网
启动工具后，会提示是否开始扫描，输入y开始扫描。

sh
复制代码
是否开始扫描？(y/n): y
工具会自动检测局域网范围，并开始扫描所有主机。扫描完成后，结果会保存到以下文件：

scan_results.csv: CSV格式的扫描结果
scan_log.txt: 详细的日志记录
scan_report.pdf: PDF格式的扫描报告
scan_report.html: HTML格式的扫描报告
配置
如果需要手动配置局域网范围，可以修改代码中的默认值：

python
复制代码
def get_local_network_range():
    return '192.168.1.0/24'  # 修改为你的局域网范围
贡献
如果你想要贡献代码或报告问题，欢迎提交Pull Request或Issue：

Fork 本仓库
创建新的分支 (git checkout -b feature-branch)
提交你的修改 (git commit -am 'Add new feature')
推送到分支 (git push origin feature-branch)
创建一个新的 Pull Request
许可
MIT License

维护者
Your Name
致谢
感谢所有参与和支持Network Scanner项目的人。

csharp
复制代码

你可以将上述内容复制并保存为`README.md`文件，然后与其他代码一起提交到GitHub。

```sh
# 创建 README.md 文件并将内容复制进去
nano README.md

# 添加 README.md 文件到 Git 仓库
git add README.md
git commit -m "Add README file"
git push origin master
希望这个README文件能帮助其他用户快速上手和使用你的网络扫描工具！如果你有任何其他问题或需要进一步的帮助，请告诉我。
