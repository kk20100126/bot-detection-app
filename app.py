%%writefile app.py
# app.py - CSV/LOG/TXT対応版 Streamlit Webダッシュボード
import re
from datetime import datetime
import pandas as pd
import streamlit as st
from tree_engine import evaluate_ip

st.set_page_config(
    page_title="Bot Detection System", page_icon="🛡️", layout="wide"
)

st.title("🛡️ 決定木型 ボット・高度サイバー攻撃検知システム")
st.caption("Zスコア / 二項分布 / HHI指数 / Byte分散 統合診断ダッシュボード")

# サイドバーでCSVも許可する
st.sidebar.header("操作パネル")
uploaded_file = st.sidebar.file_uploader(
    "アクセスログ (.log / .txt / .csv) をアップロード",
    type=["log", "txt", "csv"],
)


def parse_log_data(file):
    """LOG / TXT / CSV（表形式 & テキスト形式）の自動判別パース処理"""
    ip_logs = {}

    # 1. ヘッダー付きの構造化CSVファイルとしてパースを試みる
    if file.name.endswith(".csv"):
        try:
            df = pd.read_csv(file)
            col_map = {str(col).lower(): col for col in df.columns}

            # 列名の表記ゆれを柔軟に検索
            ip_col = next((c for c in df.columns if "ip" in str(c).lower()), None)
            time_col = next(
                (
                    c
                    for c in df.columns
                    if any(k in str(c).lower() for k in ["time", "date", "日時"])
                ),
                None,
            )
            status_col = next(
                (c for c in df.columns if "status" in str(c).lower()), None
            )
            url_col = next(
                (
                    c
                    for c in df.columns
                    if any(k in str(c).lower() for k in ["url", "path", "req"])
                ),
                None,
            )
            bytes_col = next(
                (
                    c
                    for c in df.columns
                    if any(k in str(c).lower() for k in ["byte", "size"])
                ),
                None,
            )

            if ip_col and time_col:
                for _, row in df.iterrows():
                    ip = str(row[ip_col]).strip()
                    time_raw = str(row[time_col]).strip()

                    dt = None
                    for fmt in (
                        "%d/%b/%Y:%H:%M:%S",
                        "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%d %H:%M:%S",
                        "%Y/%m/%d %H:%M:%S",
                    ):
                        try:
                            dt = datetime.strptime(time_raw.split(".")[0], fmt)
                            break
                        except ValueError:
                            continue

                    if dt:
                        status = (
                            int(row[status_col])
                            if status_col and str(row[status_col]).isdigit()
                            else 200
                        )
                        url = str(row[url_col]) if url_col else "/"
                        raw_b = (
                            row[bytes_col]
                            if bytes_col and pd.notna(row[bytes_col])
                            else 0
                        )
                        try:
                            b_val = int(raw_b)
                        except ValueError:
                            b_val = 0

                        ip_logs.setdefault(
                            ip,
                            {
                                "timestamps": [],
                                "statuses": [],
                                "urls": [],
                                "bytes": [],
                            },
                        )
                        ip_logs[ip]["timestamps"].append(dt)
                        ip_logs[ip]["statuses"].append(status)
                        ip_logs[ip]["urls"].append(url)
                        ip_logs[ip]["bytes"].append(b_val)

                if ip_logs:
                    return ip_logs
        except Exception:
            pass  # 表形式で失敗した場合はテキスト形式パースへ進む

    # 2. テキスト形式（.log, .txt, 単一文字列型.csv）の正規表現パース
    file.seek(0)
    log_text = file.getvalue().decode("utf-8", errors="ignore")
    lines = log_text.strip().split("\n")

    pattern = r"(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<time>.*?)\] [\"'](?P<method>\w+)\s+(?P<url>\S+).*?[\"'] (?P<status>\d+) (?P<bytes>\d+|-)"

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
                "%Y/%m/%d %H:%M:%S",
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

    return ip_logs


if uploaded_file is not None:
    ip_logs = parse_log_data(uploaded_file)

    if not ip_logs:
        st.error(
            "⚠️ ログ解析に失敗しました。ファイル内のIPアドレスや日時の記述形式を確認してください。"
        )
    else:
        results = [evaluate_ip(ip, data) for ip, data in ip_logs.items()]
        df_results = pd.DataFrame(results)

        st.subheader("📊 解析サマリー")
        c1, c2, c3 = st.columns(3)
        c1.metric("総解析IP数", len(df_results))
        c2.metric(
            "警告・危険IP数",
            len(df_results[df_results["最終判定"].str.contains("⚠️|🚨")]),
        )
        c3.metric(
            "正常IP数",
            len(df_results[df_results["最終判定"].str.contains("✅")]),
        )

        st.markdown("---")

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

        csv = df_results.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "📥 解析結果をCSVダウンロード",
            csv,
            "bot_detection_result.csv",
            "text/csv",
        )
else:
    st.info(
        "👈 左側のサイドバーからアクセスログファイル（.log / .txt / .csv）を選んでアップロードしてください。"
    )
