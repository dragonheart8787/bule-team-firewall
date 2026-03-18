#!/bin/bash

# 企業級 WAF 系統部署腳本
set -e

ENVIRONMENT=${1:-staging}
NAMESPACE=${2:-waf-system}

echo "🚀 部署 WAF 系統到 $ENVIRONMENT 環境..."

# 檢查必要工具
command -v kubectl >/dev/null 2>&1 || { echo "kubectl 未安裝"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker 未安裝"; exit 1; }

# 建立命名空間
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# 部署配置
if [ "$ENVIRONMENT" = "production" ]; then
    echo "📦 部署生產環境配置..."
    kubectl apply -f k8s/waf-deployment.yaml -n $NAMESPACE
    
    # 設定資源限制
    kubectl patch deployment waf-proxy -n $NAMESPACE -p '{"spec":{"template":{"spec":{"containers":[{"name":"waf-proxy","resources":{"requests":{"memory":"512Mi","cpu":"500m"},"limits":{"memory":"1Gi","cpu":"1000m"}}}]}}}}'
    
    # 設定副本數
    kubectl scale deployment waf-proxy --replicas=5 -n $NAMESPACE
    
elif [ "$ENVIRONMENT" = "staging" ]; then
    echo "📦 部署測試環境配置..."
    kubectl apply -f k8s/waf-deployment.yaml -n $NAMESPACE
    
    # 設定較少的資源
    kubectl patch deployment waf-proxy -n $NAMESPACE -p '{"spec":{"template":{"spec":{"containers":[{"name":"waf-proxy","resources":{"requests":{"memory":"128Mi","cpu":"100m"},"limits":{"memory":"256Mi","cpu":"250m"}}}]}}}}'
    
    # 設定副本數
    kubectl scale deployment waf-proxy --replicas=2 -n $NAMESPACE
    
else
    echo "❌ 不支援的環境: $ENVIRONMENT"
    exit 1
fi

# 等待部署完成
echo "⏳ 等待部署完成..."
kubectl wait --for=condition=available --timeout=300s deployment/waf-proxy -n $NAMESPACE

# 檢查健康狀態
echo "🔍 檢查服務健康狀態..."
kubectl get pods -n $NAMESPACE
kubectl get services -n $NAMESPACE

# 執行健康檢查
echo "🏥 執行健康檢查..."
kubectl run health-check --image=curlimages/curl --rm -i --restart=Never -- curl -f http://waf-proxy-service:8080/healthz

echo "✅ 部署完成！"
echo "📊 監控儀表板: http://localhost:3000"
echo "🔧 管理介面: http://localhost:8080/api/blocklist"

