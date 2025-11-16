#!/bin/bash

# 住宅代理VPN一键部署脚本
# 适用于Ubuntu 20.04+系统
# 作者：鲍旭东
# 微信：xudong_xyq
# 版本：1.0

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 配置参数（请根据实际情况修改）
RESIDENTIAL_IP="92.112.246.140"
RESIDENTIAL_PORT="32066"
RESIDENTIAL_USER="xifeibao"
RESIDENTIAL_PASS="xiFEI21988"
VPS_PORT="443"

# 输出函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用root权限运行此脚本"
        exit 1
    fi
}

# 系统更新
system_update() {
    log_info "更新系统包..."
    apt update && apt upgrade -y
    log_info "系统更新完成"
}

# 安装依赖
install_dependencies() {
    log_info "安装必要依赖..."
    apt install -y wget curl git qrencode net-tools ufw
    log_info "依赖安装完成"
}

# 安装Xray
install_xray() {
    log_info "安装Xray核心..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    log_info "Xray安装完成"
}

# 配置Xray
configure_xray() {
    log_info "配置Xray服务..."
    
    # 生成UUID
    UUID=$(cat /proc/sys/kernel/random/uuid)
    
    # 创建配置文件
    cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": ${VPS_PORT},
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "alterId": 0,
            "security": "auto"
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "socks",
      "settings": {
        "servers": [
          {
            "address": "${RESIDENTIAL_IP}",
            "port": ${RESIDENTIAL_PORT},
            "users": [
              {
                "user": "${RESIDENTIAL_USER}",
                "pass": "${RESIDENTIAL_PASS}"
              }
            ]
          }
        ]
      },
      "tag": "residential-proxy"
    },
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "outboundTag": "residential-proxy",
        "domain": ["geosite:google", "geosite:facebook", "geosite:tiktok", "geosite:youtube", "geosite:instagram", "geosite:twitter"]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": ["geosite:cn"]
      },
      {
        "type": "field",
        "outboundTag": "block",
        "domain": ["geosite:category-ads-all"]
      }
    ]
  }
}
EOF

    # 创建优化的systemd服务
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    log_info "Xray配置完成"
}

# 系统优化
system_optimization() {
    log_info "优化系统参数..."
    
    # 内核优化
    cat > /etc/sysctl.d/99-xray-optimization.conf << EOF
# 带宽优化
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 65536
net.core.wmem_default = 65536
net.core.optmem_max = 65536
net.core.netdev_max_backlog = 4096

# TCP优化
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3

# 连接数优化
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
EOF

    sysctl -p /etc/sysctl.d/99-xray-optimization.conf
    log_info "系统优化完成"
}

# 配置防火墙
configure_firewall() {
    log_info "配置防火墙..."
    ufw --force enable
    ufw allow 22/tcp
    ufw allow ${VPS_PORT}/tcp
    log_info "防火墙配置完成"
}

# 启动服务
start_services() {
    log_info "启动Xray服务..."
    systemctl daemon-reload
    systemctl enable xray
    systemctl start xray
    
    # 等待服务启动
    sleep 3
    
    # 检查服务状态
    if systemctl is-active --quiet xray; then
        log_info "Xray服务启动成功"
    else
        log_error "Xray服务启动失败"
        exit 1
    fi
}

# 生成客户端配置
generate_client_config() {
    log_info "生成客户端配置..."
    
    # 获取配置信息
    CONFIG_FILE="/usr/local/etc/xray/config.json"
    UUID=$(grep -o '"id": "[^"]*' $CONFIG_FILE | head -1 | cut -d'"' -f4)
    SERVER_IP=$(curl -s https://ifconfig.me)
    
    # 生成VMess链接
    VMESS_CONFIG=$(cat << EOF
{
  "v": "2",
  "ps": "Residential-Proxy-VPN",
  "add": "${SERVER_IP}",
  "port": "${VPS_PORT}",
  "id": "${UUID}",
  "aid": "0",
  "scy": "auto",
  "net": "tcp",
  "type": "none",
  "host": "",
  "path": "",
  "tls": "none"
}
EOF
)
    
    VMESS_URL="vmess://$(echo "${VMESS_CONFIG}" | base64 -w0)"
    
    # 显示配置信息
    echo
    log_info "=== 部署完成 ==="
    echo "服务器: ${SERVER_IP}"
    echo "端口: ${VPS_PORT}"
    echo "UUID: ${UUID}"
    echo "加密: auto"
    echo "传输: tcp"
    echo "住宅代理: ${RESIDENTIAL_IP}:${RESIDENTIAL_PORT}"
    echo "=================="
    echo
    
    # 生成二维码
    echo "${VMESS_URL}" | qrencode -t UTF8
    echo
    echo "VMess链接: ${VMESS_URL}"
    echo
    
    # 保存配置到文件
    cat > /root/vpn_config.txt << EOF
=== 住宅代理VPN配置 ===
服务器: ${SERVER_IP}
端口: ${VPS_PORT}
UUID: ${UUID}
加密: auto
传输: tcp

住宅代理信息:
IP: ${RESIDENTIAL_IP}
端口: ${RESIDENTIAL_PORT}
用户名: ${RESIDENTIAL_USER}
密码: ${RESIDENTIAL_PASS}

VMess链接:
${VMESS_URL}

客户端配置:
- 类型: VMess
- 地址: ${SERVER_IP}
- 端口: ${VPS_PORT}
- 用户ID: ${UUID}
- 加密: auto
- 传输: tcp
EOF

    log_info "配置已保存到: /root/vpn_config.txt"
}

# 验证部署
verify_deployment() {
    log_info "验证部署..."
    
    # 检查服务状态
    if systemctl is-active --quiet xray; then
        log_info "✅ Xray服务运行正常"
    else
        log_error "❌ Xray服务未运行"
        return 1
    fi
    
    # 检查端口监听
    if netstat -tlnp | grep -q ":${VPS_PORT}.*xray"; then
        log_info "✅ Xray正在监听端口 ${VPS_PORT}"
    else
        log_error "❌ Xray未监听端口 ${VPS_PORT}"
        return 1
    fi
    
    # 测试住宅代理连通性
    log_info "测试住宅代理连通性..."
    if curl --socks5 ${RESIDENTIAL_USER}:${RESIDENTIAL_PASS}@${RESIDENTIAL_IP}:${RESIDENTIAL_PORT} --connect-timeout 10 -I https://www.google.com >/dev/null 2>&1; then
        log_info "✅ 住宅代理连接正常"
    else
        log_warn "⚠️  住宅代理连接测试失败，请检查代理状态"
    fi
    
    log_info "✅ 部署验证完成"
}

# 显示使用说明
show_usage() {
    cat << EOF

使用方法：
1. 使用root权限运行此脚本
2. 确保已正确设置住宅代理参数
3. 脚本将自动完成所有部署步骤

管理命令：
sudo systemctl status xray    # 查看服务状态
sudo systemctl restart xray   # 重启服务
sudo journalctl -u xray -f    # 查看实时日志

客户端配置：
使用生成的二维码或VMess链接在小火箭/V2RayNG中配置

EOF
}

# 主函数
main() {
    log_info "开始部署住宅代理VPN..."
    check_root
    system_update
    install_dependencies
    install_xray
    configure_xray
    system_optimization
    configure_firewall
    start_services
    generate_client_config
    verify_deployment
    show_usage
    log_info "部署完成！"
}

# 执行主函数
main "$@"