# tree_engine.py - 決定木と統合評価ロジック
import nodes


def evaluate_ip(ip, data):
    """1つのIPアドレスに対する決定木評価を実行"""
    f1 = nodes.test_macro_error_rate(data["statuses"])
    f2, z_score = nodes.test_micro_zscore(data["timestamps"])
    f3, hhi_val = nodes.test_hhi_diversity(data["urls"])
    f4, byte_std = nodes.test_byte_variance(data["bytes"])

    # アイコンによる判定パイプラインステータス
    pipeline = f"Macro:[{'🚨' if f1 else '✅'}] Micro:[{'🚨' if f2 else '✅'}] HHI:[{'🚨' if f3 else '✅'}] Byte:[{'🚨' if f4 else '✅'}]"

    # 決定木ルール
    if f1 and f2:
        verdict = "🚨 HIGH RISK (多重違反: エラー&周期)"
        path = "Node1 ➔ Node2 ➔ FAIL"
    elif f1:
        verdict = "⚠️ BRUTE FORCE (大量エラー)"
        path = "Node1 ➔ FAIL"
    elif f2:
        verdict = "⚠️ STEALTH BOT (隠蔽周期通信)"
        path = "Node1 ➔ Node2 ➔ FAIL"
    elif f3:
        verdict = "⚠️ RECON/SCRAPER (アクセス偏向)"
        path = "Node1 ➔ Node2 ➔ Node3 ➔ FAIL"
    elif f4:
        verdict = "⚠️ FIXED BOT (固定ペイロード)"
        path = "Node1 ➔ Node2 ➔ Node3 ➔ Node4 ➔ FAIL"
    else:
        verdict = "✅ NORMAL (正常通信)"
        path = "All Nodes ➔ PASS"

    return {
        "IP Address": ip,
        "アクセス数": len(data["timestamps"]),
        "判定パイプライン": pipeline,
        "トレース": path,
        "最終判定": verdict,
        "Z-Score": z_score,
        "HHI指数": hhi_val,
    }
