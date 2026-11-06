# app.py - StreamlitによるWebダッシュボード画面
import re
from datetime import datetime
import pandas as pd
import streamlit as st
from tree_engine import evaluate_ip

# 画面設定
st.set_page_config(
    page_title="Bot Detection System", page_icon="🛡️", layout="wide"
)

st.title("🛡️ 決定木型 ボット・高度サイバー攻撃検知システム")
st.caption("Zスコア / 二項分布 / HHI指数 / Byte分散 統合診断ダッシュボード")

# サイドバー
st.sidebar.header("操作パネル")
uploaded_file = st.sidebar.file_uploader(
    "アクセスログ (.log / .txt) をアップロード", type=["log", "txt"]
)

if uploaded_file is not None:
    log_text = uploaded_file.getvalue().decode("utf-8", errors="ignore")
    lines = log_text.strip().split("\n")

    pattern = r"(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<time>.*?)\] [\"'](?P<method>\w+)\s+(?P<url>\S+).*?[\"'] (?P<status>\d+) (?P<bytes>\d+|-)"
    ip_logs = {}

    for line in lines:
        match = re.search(pattern, line)
        if match:
            ip = match.group("ip")
            time_raw = match.group("time").split(" ")[0]
            dt = None
            for fmt in (
                "%d/%b/%Y:%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    dt = datetime.strptime(time_raw, fmt)
                    break
                except ValueError:
                    continue
            if dt:
                raw_bytes = match.group("bytes")
                ip_logs.setdefault(
                    ip,
                    {"timestamps": [], "statuses": [], "urls": [], "bytes": []},
                )
                ip_logs[ip]["timestamps"].append(dt)
                ip_logs[ip]["statuses"].append(int(match.group("status")))
                ip_logs[ip]["urls"].append(match.group("url"))
                ip_logs[ip]["bytes"].append(
                    int(raw_bytes) if raw_bytes.isdigit() else 0
                )

    # 決定木エンジンの呼び出し
    results = [evaluate_ip(ip, data) for ip, data in ip_logs.items()]
    df_results = pd.DataFrame(results)

    # メトリクスカード
    st.subheader("📊 解析サマリー")
    c1, c2, c3 = st.columns(3)
    c1.metric("総解析IP数", len(df_results))
    c2.metric(
        "警告・危険IP数",
        len(df_results[df_results["最終判定"].str.contains("⚠️|🚨")]),
    )
    c3.metric(
        "正常IP数", len(df_results[df_results["最終判定"].str.contains("✅")])
    )

    st.markdown("---")

    # フィルターとテーブル表示
    st.subheader("🔍 判定結果一覧")
    filter_opt = st.radio(
        "表示切り替え",
        ["全件表示", "危険・警告のみ", "正常のみ"],
        horizontal=True,
    )
    if filter_opt == "危険・警告のみ":
        df_show = df_results[df_results["最終判定"].str.contains("⚠️|🚨")]
    elif filter_opt == "正常のみ":
        df_show = df_results[df_results["最終判定"].str.contains("✅")]
    else:
        df_show = df_results

    st.dataframe(df_show, use_container_width=True)

    # CSVダウンロード
    csv = df_results.to_csv(index=False).encode("utf-8-sig")
    st.download_button(
        "📥 解析結果をCSVダウンロード",
        csv,
        "bot_detection_result.csv",
        "text/csv",
    )
else:
    st.info(
        "👈 左側のサイドバーからアクセスログファイルを選んでアップロードしてください。"
    )
