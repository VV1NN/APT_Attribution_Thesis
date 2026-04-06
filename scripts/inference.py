#!/usr/bin/env python3
"""
APT IoC 歸因推論 Pipeline。

用法：
  uv run python scripts/inference.py <IoC>
  uv run python scripts/inference.py d54fa56f1a0b1b63c...     # SHA-256
  uv run python scripts/inference.py evil-c2.xyz               # domain
  uv run python scripts/inference.py 185.45.67.89              # IP
  uv run python scripts/inference.py --file iocs.txt           # 批次（每行一個 IoC）

流程：
  1. 類型判斷（regex）
  2. VT Details API 查詢
  3. VT Relationships API 查詢（每種邊最多 50 個）
  4. 載入 Master KG overlap_dict + vocabularies + Node2Vec + XGBoost model
  5. 四層特徵提取（209d）
  6. predict_proba → Top-K + 信心度
"""

import argparse
import json
import logging
import math
import os
import pickle
import re
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import requests
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"
RATE_LIMIT = 0.1  # seconds between requests

MODEL_DIR = Path("scripts/model")
KG_JSON = Path("knowledge_graphs/master/merged_kg.json")
VOCAB_PATH = Path("scripts/vocabularies.json")
N2V_PATH = Path("scripts/features/node2vec_embeddings.npz")
CALIBRATOR_PATH = MODEL_DIR / "calibrator.pkl"


# ════════════════════════════════════════════════════════════
# IoC Type Detection
# ════════════════════════════════════════════════════════════

RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
RE_DOMAIN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$")


def detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip().lower()
    if RE_SHA256.match(ioc):
        return "file"
    if RE_SHA1.match(ioc):
        return "file"
    if RE_MD5.match(ioc):
        return "file"
    if RE_IPV4.match(ioc):
        return "ip"
    if RE_DOMAIN.match(ioc):
        return "domain"
    raise ValueError(f"Unknown IoC type: {ioc}")


def make_node_id(ioc_type: str, ioc_value: str, vt_detail: dict) -> str:
    if ioc_type == "file":
        sha256 = vt_detail.get("sha256") or ioc_value
        return f"file_{sha256}"
    elif ioc_type == "domain":
        return f"domain_{ioc_value}"
    elif ioc_type == "ip":
        return f"ip_{ioc_value}"
    return f"{ioc_type}_{ioc_value}"


# ════════════════════════════════════════════════════════════
# VT API
# ════════════════════════════════════════════════════════════

def vt_request(url: str) -> dict | None:
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.json().get("data", {})
        elif resp.status_code == 404:
            return None
        elif resp.status_code == 429:
            logger.warning("Rate limited, waiting 60s...")
            time.sleep(60)
            return vt_request(url)
        else:
            logger.error(f"VT API error {resp.status_code}: {resp.text[:200]}")
            return None
    except Exception as e:
        logger.error(f"VT API request failed: {e}")
        return None


def query_vt_detail(ioc_type: str, ioc_value: str) -> dict | None:
    """查 VT Details API，回傳 attributes dict。"""
    endpoint_map = {"file": "files", "domain": "domains", "ip": "ip_addresses"}
    endpoint = endpoint_map.get(ioc_type)
    if not endpoint:
        return None
    url = f"{VT_BASE}/{endpoint}/{ioc_value}"
    time.sleep(RATE_LIMIT)
    data = vt_request(url)
    if data is None:
        return None
    return data.get("attributes", {})


def query_vt_relationships(ioc_type: str, ioc_value: str) -> dict:
    """查 VT Relationships API，回傳 {rel_type: [(target_id, target_attrs), ...]}。"""
    rel_map = {
        "file": ["contacted_ips", "contacted_domains", "contacted_urls",
                 "dropped_files", "execution_parents", "bundled_files"],
        "domain": ["resolutions", "communicating_files", "referrer_files", "subdomains"],
        "ip": ["resolutions", "communicating_files", "referrer_files"],
    }
    rels = rel_map.get(ioc_type, [])
    endpoint_map = {"file": "files", "domain": "domains", "ip": "ip_addresses"}
    endpoint = endpoint_map.get(ioc_type)

    result = {}
    for rel in rels:
        url = f"{VT_BASE}/{endpoint}/{ioc_value}/{rel}?limit=40"
        time.sleep(RATE_LIMIT)
        data = vt_request(url)
        if data is None:
            continue

        neighbors = []
        items = data if isinstance(data, list) else [data]
        # VT returns paginated results
        if isinstance(data, dict) and "data" in data:
            items = data["data"] if isinstance(data["data"], list) else [data["data"]]
        elif isinstance(data, dict) and "id" in data:
            items = [data]

        for item in items[:50]:
            if isinstance(item, dict):
                attrs = item.get("attributes", {})
                item_id = item.get("id", "")
                item_type = item.get("type", "")
                neighbors.append({"id": item_id, "type": item_type, "attributes": attrs})

        if neighbors:
            result[rel] = neighbors
            logger.info(f"  {rel}: {len(neighbors)} neighbors")

    return result


# ════════════════════════════════════════════════════════════
# Feature Extraction (reuse build_features.py functions)
# ════════════════════════════════════════════════════════════

import sys
sys.path.insert(0, str(Path(__file__).parent))
from build_features import (
    extract_l1, extract_l3, extract_l2, extract_l4,
    L1_NAMES, L2_NAMES, L4_NAMES, get_l3_names, _entropy,
    EDGE_TYPES, L2_NAMES,
)
import build_features as bf


# ════════════════════════════════════════════════════════════
# Inference Engine
# ════════════════════════════════════════════════════════════

class APTInferenceEngine:
    def __init__(self):
        logger.info("Loading inference engine...")
        self._load_model()
        self._load_kg()
        self._load_vocabs()
        self._load_n2v()
        logger.info("Engine ready.")

    def _load_model(self):
        from xgboost import XGBClassifier
        with open(MODEL_DIR / "config.json") as f:
            self.config = json.load(f)
        self.clf = XGBClassifier()
        self.clf.load_model(MODEL_DIR / "xgboost_model.json")
        with open(MODEL_DIR / "imputer.pkl", "rb") as f:
            self.imputer = pickle.load(f)
        with open(MODEL_DIR / "label_encoder.pkl", "rb") as f:
            self.le = pickle.load(f)
        self.org_list = self.config["org_list"]
        self.threshold = self.config["confidence_threshold"]
        self.calibrator = {
            "method": "identity",
            "temperature": 1.0,
            "low_confidence_threshold": float(self.threshold),
            "open_set_conf_threshold": float(max(self.threshold + 0.12, 0.42)),
            "conflict_margin_threshold": 0.08,
        }
        if CALIBRATOR_PATH.exists():
            with open(CALIBRATOR_PATH, "rb") as f:
                loaded = pickle.load(f)
            if isinstance(loaded, dict):
                self.calibrator.update(loaded)

        self.low_confidence_threshold = float(self.calibrator.get("low_confidence_threshold", self.threshold))
        self.open_set_conf_threshold = float(
            self.calibrator.get("open_set_conf_threshold", max(self.threshold + 0.12, 0.42))
        )
        self.conflict_margin_threshold = float(self.calibrator.get("conflict_margin_threshold", 0.08))
        logger.info(
            f"  Model: {self.config['n_total']}d, {len(self.org_list)} orgs, "
            f"threshold={self.threshold}, calibrator={self.calibrator.get('method', 'identity')}"
        )

    @staticmethod
    def _softmax(v):
        z = v - np.max(v)
        ez = np.exp(z)
        return ez / max(float(np.sum(ez)), 1e-12)

    def _calibrate_proba(self, proba):
        method = str(self.calibrator.get("method", "identity"))
        if method != "temperature_scaling":
            return proba.astype(np.float32)
        t = max(float(self.calibrator.get("temperature", 1.0)), 1e-6)
        logits = np.log(np.clip(proba.astype(np.float64), 1e-12, 1.0))
        return self._softmax(logits / t).astype(np.float32)

    def _load_kg(self):
        logger.info("  Loading Master KG (for overlap dict + adjacency)...")
        with open(KG_JSON) as f:
            data = json.load(f)

        self.nodes = {}
        for n in data["nodes"]:
            self.nodes[n["id"]] = {
                "type": n.get("type"),
                "depth": n.get("depth"),
                "attributes": n.get("attributes") or {},
                "orgs": set(n.get("orgs") or []),
            }

        self.adj = defaultdict(set)
        self.edge_by_node = defaultdict(list)
        for e in data["edges"]:
            rel = e.get("relationship", "unknown")
            src, tgt = e["source"], e["target"]
            if rel == "has_ioc" or self.nodes.get(src, {}).get("type") == "apt" or self.nodes.get(tgt, {}).get("type") == "apt":
                continue
            self.adj[src].add(tgt)
            self.adj[tgt].add(src)
            ea = e.get("attributes") or {}
            self.edge_by_node[src].append((tgt, rel, ea))
            self.edge_by_node[tgt].append((src, rel, ea))

        # ALL-nodes overlap dict
        self.overlap_dict = {nid: nd["orgs"] for nid, nd in self.nodes.items()
                             if nd["type"] != "apt" and nd["orgs"]}
        bf._node_attrs = {nid: nd["attributes"] for nid, nd in self.nodes.items()}
        logger.info(f"  KG: {len(self.nodes)} nodes, overlap_dict: {len(self.overlap_dict)}")

    def _load_vocabs(self):
        with open(VOCAB_PATH) as f:
            vdata = json.load(f)
        self.vocabs = vdata["vocabs"]
        self.value_counts = vdata["value_counts"]
        self.freq_tables = vdata["freq"]

    def _load_n2v(self):
        if N2V_PATH.exists():
            data = np.load(N2V_PATH, allow_pickle=True)
            self.n2v = {str(nid): emb for nid, emb in zip(data["node_ids"], data["embeddings"])}
            logger.info(f"  Node2Vec: {len(self.n2v)} embeddings")
        else:
            self.n2v = {}

    def infer(self, ioc: str, top_k: int = 5) -> dict:
        """對單一 IoC 執行歸因推論。"""
        ioc = ioc.strip().lower()
        result = {"ioc": ioc, "status": "unknown"}

        # Step 1: 類型判斷
        try:
            ioc_type = detect_ioc_type(ioc)
        except ValueError as e:
            result["error"] = str(e)
            return result
        result["ioc_type"] = ioc_type
        logger.info(f"IoC: {ioc} (type={ioc_type})")

        # Step 2: VT Details
        logger.info("Querying VT Details...")
        vt_detail = query_vt_detail(ioc_type, ioc)
        if vt_detail is None:
            result["status"] = "not_found"
            result["error"] = "Not found in VirusTotal"
            return result
        result["detection_ratio"] = vt_detail.get("last_analysis_stats", {}).get("malicious", 0)

        # Step 3: VT Relationships
        logger.info("Querying VT Relationships...")
        vt_rels = query_vt_relationships(ioc_type, ioc)

        # 建立臨時節點 + 鄰居
        node_id = make_node_id(ioc_type, ioc, vt_detail)
        # 標準化 VT detail 為我們的 attributes 格式
        attrs = self._normalize_vt_attrs(ioc_type, vt_detail)
        temp_node = {"type": ioc_type, "depth": None, "attributes": attrs, "orgs": set()}

        # 收集鄰居並加入臨時 adj
        temp_adj = set(self.adj.get(node_id, set()))  # 已在 KG 中的鄰居
        temp_edge_by_node = list(self.edge_by_node.get(node_id, []))
        new_neighbor_count = 0

        for rel_type, neighbors in vt_rels.items():
            edge_rel = self._map_rel_type(rel_type, ioc_type)
            for nb in neighbors[:50]:
                nb_id = self._make_neighbor_id(nb, rel_type)
                if nb_id and nb_id != node_id:
                    temp_adj.add(nb_id)
                    temp_edge_by_node.append((nb_id, edge_rel, {}))
                    new_neighbor_count += 1

        logger.info(f"Neighbors: {len(temp_adj)} total ({new_neighbor_count} from VT, "
                     f"{len(temp_adj) - new_neighbor_count} already in KG)")

        # 暫時加入全域結構供特徵提取使用
        bf._node_attrs[node_id] = attrs
        orig_adj = self.adj.get(node_id, set()).copy()
        orig_edges = self.edge_by_node.get(node_id, []).copy()
        self.adj[node_id] = temp_adj
        self.edge_by_node[node_id] = temp_edge_by_node

        # Step 4: 四層特徵提取
        logger.info("Extracting features...")
        l3_names = get_l3_names(self.org_list)

        l1 = extract_l1(node_id, temp_node, self.vocabs, self.value_counts, self.freq_tables)
        l2 = extract_l2(node_id, self.adj, self.edge_by_node, self.nodes)
        l3 = extract_l3(node_id, self.adj, self.overlap_dict, self.org_list, exclude_org=None)
        l4 = extract_l4(node_id, self.adj, self.n2v)

        x = np.array(l1 + l2 + list(l3) + list(l4), dtype=np.float32).reshape(1, -1)
        x_imp = self.imputer.transform(x)

        # Step 5: 預測
        proba_raw = self.clf.predict_proba(x_imp)[0]
        proba_cal = self._calibrate_proba(proba_raw)
        top_indices = np.argsort(proba_cal)[::-1][:top_k]

        predictions = []
        for idx in top_indices:
            org = self.le.classes_[idx]
            prob_cal = float(proba_cal[idx])
            prob_raw = float(proba_raw[idx])
            predictions.append(
                {"org": org, "probability": prob_cal, "probability_raw": prob_raw}
            )

        confidence_raw = float(proba_raw[top_indices[0]])
        confidence_cal = float(proba_cal[top_indices[0]])
        margin = float(proba_cal[top_indices[0]] - proba_cal[top_indices[1]]) if len(top_indices) > 1 else confidence_cal

        overlap_stats = {
            "overlap_ratio": float(l3[3]) if len(l3) > 3 else 0.0,
            "distinct_orgs": int(l3[4]) if len(l3) > 4 else 0,
            "dominant_ratio": float(l3[5]) if len(l3) > 5 else 0.0,
        }

        abstain_reason = None
        # High conflict: small class margin OR KG overlap suggests fragmented attribution.
        if margin < self.conflict_margin_threshold or (
            overlap_stats["distinct_orgs"] >= 3 and overlap_stats["dominant_ratio"] < 0.40
        ):
            abstain_reason = "high_conflict"
        # Open-set suspicion: low confidence with weak KG overlap.
        elif confidence_cal < self.open_set_conf_threshold and overlap_stats["overlap_ratio"] < 0.05:
            abstain_reason = "open_set"
        # Generic confidence fallback.
        elif confidence_cal < self.low_confidence_threshold:
            abstain_reason = "low_confidence"

        decision = "ABSTAIN" if abstain_reason else "PREDICT"
        attributed = decision == "PREDICT"

        result["status"] = "attributed" if attributed else "unknown"
        result["decision"] = decision
        result["abstain_reason"] = abstain_reason
        result["confidence"] = confidence_cal
        result["confidence_raw"] = confidence_raw
        result["confidence_calibrated"] = confidence_cal
        result["confidence_margin"] = margin
        result["open_set_score"] = float(1.0 - confidence_cal)
        result["threshold"] = self.low_confidence_threshold
        result["thresholds"] = {
            "low_confidence": self.low_confidence_threshold,
            "open_set": self.open_set_conf_threshold,
            "conflict_margin": self.conflict_margin_threshold,
        }
        result["top_k"] = predictions
        result["overlap_stats"] = overlap_stats

        # 還原臨時修改
        self.adj[node_id] = orig_adj
        self.edge_by_node[node_id] = orig_edges

        return result

    def _normalize_vt_attrs(self, ioc_type, vt_detail):
        """將 VT API 回傳的 attributes 標準化為 KG 格式。"""
        a = {}
        stats = vt_detail.get("last_analysis_stats", {})
        a["malicious"] = stats.get("malicious", 0)
        a["suspicious"] = stats.get("suspicious", 0)
        a["harmless"] = stats.get("harmless", 0)
        a["undetected"] = stats.get("undetected", 0)
        total = sum(stats.values()) if stats else 0
        a["detection_ratio"] = a["malicious"] / max(total, 1)
        a["reputation"] = vt_detail.get("reputation")

        if ioc_type == "file":
            a["size"] = vt_detail.get("size")
            a["type_tag"] = vt_detail.get("type_tag")
            a["type_extension"] = vt_detail.get("type_extension")
            a["type_description"] = vt_detail.get("type_description")
            a["pe_info"] = vt_detail.get("pe_info")
            a["creation_time"] = vt_detail.get("creation_date")
            a["first_seen_itw"] = vt_detail.get("first_seen_itw_date")
            a["first_submission"] = vt_detail.get("first_submission_date")
            a["last_submission"] = vt_detail.get("last_submission_date")
            a["last_analysis"] = vt_detail.get("last_analysis_date")
            a["times_submitted"] = vt_detail.get("times_submitted")
            a["unique_sources"] = vt_detail.get("unique_sources")
            a["total_votes"] = vt_detail.get("total_votes")
            a["signature_verified"] = vt_detail.get("signature_info", {}).get("verified") if vt_detail.get("signature_info") else None
            a["packers"] = vt_detail.get("packers")
            a["popular_threat_classification"] = vt_detail.get("popular_threat_classification")
            a["tags"] = vt_detail.get("tags", [])
            a["bundle_info"] = vt_detail.get("bundle_info")
            a["file_version_info"] = vt_detail.get("additional_info", {}).get("exiftool") if vt_detail.get("additional_info") else None
            a["sha256"] = vt_detail.get("sha256")

        elif ioc_type == "domain":
            a["registrar"] = vt_detail.get("registrar")
            a["tld"] = vt_detail.get("tld")
            a["creation_date"] = vt_detail.get("creation_date")
            a["last_update_date"] = vt_detail.get("last_modification_date")
            a["categories"] = vt_detail.get("categories", {})
            a["has_whois"] = bool(vt_detail.get("whois"))
            a["last_dns_records"] = vt_detail.get("last_dns_records", [])
            a["jarm"] = vt_detail.get("jarm")
            a["total_votes"] = vt_detail.get("total_votes")
            a["tags"] = vt_detail.get("tags", [])

        elif ioc_type == "ip":
            a["country"] = vt_detail.get("country")
            a["continent"] = vt_detail.get("continent")
            a["asn"] = vt_detail.get("asn")
            a["as_owner"] = vt_detail.get("as_owner")
            a["network"] = vt_detail.get("network")
            a["regional_internet_registry"] = vt_detail.get("regional_internet_registry")
            a["jarm"] = vt_detail.get("jarm")
            a["last_https_certificate"] = vt_detail.get("last_https_certificate")
            a["total_votes"] = vt_detail.get("total_votes")
            a["tags"] = vt_detail.get("tags", [])

        return a

    def _map_rel_type(self, vt_rel: str, ioc_type: str) -> str:
        """VT relationship name → edge relationship name。"""
        mapping = {
            "contacted_ips": "contacted_ip",
            "contacted_domains": "contacted_domain",
            "contacted_urls": "contacted_url",
            "dropped_files": "dropped_file",
            "execution_parents": "execution_parent",
            "bundled_files": "bundled_file",
            "resolutions": "resolves_to",
            "communicating_files": "communicating_file",
            "referrer_files": "referrer_file",
            "subdomains": "has_subdomain",
        }
        return mapping.get(vt_rel, vt_rel)

    def _make_neighbor_id(self, nb: dict, rel_type: str) -> str | None:
        """從 VT relationship 回傳的鄰居資料建立 node_id。"""
        nb_type = nb.get("type", "")
        nb_id = nb.get("id", "")
        if not nb_id:
            return None

        if nb_type == "file" or rel_type in ("dropped_files", "execution_parents",
                                               "bundled_files", "communicating_files", "referrer_files"):
            return f"file_{nb_id}"
        elif nb_type == "domain" or rel_type in ("contacted_domains", "subdomains"):
            return f"domain_{nb_id}"
        elif nb_type == "ip_address" or rel_type in ("contacted_ips",):
            return f"ip_{nb_id}"
        elif rel_type == "resolutions":
            # resolutions 可能是 domain→ip 或 ip→domain
            attrs = nb.get("attributes", {})
            host = attrs.get("host_name", "")
            ip = attrs.get("ip_address", "")
            if host:
                return f"domain_{host}"
            elif ip:
                return f"ip_{ip}"
        return None


# ════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════

def print_result(result: dict):
    """格式化輸出歸因結果。"""
    print()
    print(f"{'='*60}")
    print(f"IoC:  {result['ioc']}  ({result.get('ioc_type', '?')})")
    print(f"{'='*60}")

    if result["status"] == "not_found":
        print(f"❌ {result.get('error', 'Unknown error')}")
        return

    if result["status"] == "error":
        print(f"❌ Error: {result.get('error')}")
        return

    # Top-K
    print()
    for i, pred in enumerate(result.get("top_k", []), 1):
        prob = pred["probability"]
        bar = "█" * int(prob * 30)
        marker = " ←" if i == 1 and result["status"] == "attributed" else ""
        print(f"  #{i}  {pred['org']:<22} {prob:>6.1%}  {bar}{marker}")

    print()
    conf = result.get("confidence_calibrated", result.get("confidence", 0))
    conf_raw = result.get("confidence_raw", conf)
    thr = result.get("threshold", 0.3)

    if result.get("decision") == "PREDICT":
        print(
            f"✅ 歸因結果：{result['top_k'][0]['org']}（calibrated {conf:.1%}, "
            f"raw {conf_raw:.1%}, 門檻 {thr:.0%}）"
        )
    else:
        reason = result.get("abstain_reason", "low_confidence")
        print(
            f"⚠️ 拒判（{reason}）：calibrated {conf:.1%}, raw {conf_raw:.1%}, "
            f"門檻 {thr:.0%}"
        )

    # Overlap stats
    ov = result.get("overlap_stats", {})
    if ov.get("distinct_orgs", 0) > 0:
        print(f"\n  Overlap: {ov['overlap_ratio']:.0%} 鄰居有 KG 匹配, "
              f"{ov['distinct_orgs']} 個候選 org, "
              f"最高票佔 {ov['dominant_ratio']:.0%}")
    else:
        print(f"\n  Overlap: 無 KG 匹配（冷啟動，僅依靠 VT metadata + 圖統計）")

    print()


def main():
    parser = argparse.ArgumentParser(description="APT IoC Attribution")
    parser.add_argument("ioc", nargs="?", help="Single IoC (hash/domain/IP)")
    parser.add_argument("--file", "-f", help="File with one IoC per line")
    parser.add_argument("--top-k", "-k", type=int, default=5, help="Number of top predictions")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if not VT_API_KEY:
        print("Error: VT_API_KEY not set. Add it to .env file.")
        return

    if not (MODEL_DIR / "xgboost_model.json").exists():
        print("Error: Model not found. Run: uv run python scripts/train_and_save_model.py")
        return

    engine = APTInferenceEngine()

    # Collect IoCs
    iocs = []
    if args.ioc:
        iocs.append(args.ioc)
    if args.file:
        with open(args.file) as f:
            iocs.extend(line.strip() for line in f if line.strip())

    if not iocs:
        parser.print_help()
        return

    # Run inference
    results = []
    for ioc in iocs:
        result = engine.infer(ioc, top_k=args.top_k)
        results.append(result)
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        else:
            print_result(result)

    if len(results) > 1:
        attributed = sum(1 for r in results if r["status"] == "attributed")
        print(f"\n{'='*60}")
        print(f"批次結果：{len(results)} 筆 IoC，{attributed} 筆成功歸因，"
              f"{len(results) - attributed} 筆 Unknown")


if __name__ == "__main__":
    main()
