import requests
import time
import json

# 假設這是你的 API Key
API_KEY = 'YOUR_VT_API_KEY'
HEADERS = {"x-apikey": API_KEY}

def get_ioc_data(ioc_type, ioc_value):
    """
    ioc_type: 'files', 'domains', 'ip_addresses'
    ioc_value: sha256, domain name, or ip
    """
    # 關鍵：同時索取 attributes 和特定的 relationships
    url = f"https://www.virustotal.com/api/v3/{ioc_type}/{ioc_value}?relationships=contacted_domains,contacted_ips,resolutions"
    
    response = requests.get(url, headers=HEADERS)
    
    if response.status_code == 200:
        data = response.json()
        
        # 1. 提取屬性變數 (Attributes)
        attrs = data['data']['attributes']
        features = {
            "id": data['data']['id'],
            "malicious_score": attrs['last_analysis_stats']['malicious'],
            "tags": attrs.get('tags', []),
            "first_seen": attrs.get('first_submission_date', 0),
            "reputation": attrs.get('reputation', 0)
        }
        
        # 2. 提取關聯變數 (Relationships) - 用於畫圖
        # 注意：Relationships 這裡只會有簡易 ID，詳細資料要再去拉或是看 include
        rels = data['data']['relationships']
        connected_nodes = []
        
        if 'contacted_domains' in rels:
             # 這裡通常需要處理分頁，此為簡化版
            for item in rels['contacted_domains']['data']:
                connected_nodes.append({"type": "domain", "id": item['id']})
                
        return features, connected_nodes
    else:
        print(f"Error: {response.status_code}")
        return None, None

# 測試用
# features, edges = get_ioc_data('files', '某個惡意檔案的HASH')
# print(features) 
# print(edges)