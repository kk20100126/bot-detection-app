# app.py - JSON / Zeek(conn.log) / Webログ / CSV マルチフォーマット対応版
import json
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

st.sidebar.header("操作パネル")
uploaded_file = st.sidebar.file_uploader(
    "アクセスログ (.log / .txt / .csv / .json) をアップロード",
    type=["log", "txt", "csv", "json"],
)


def parse_json_log(file):
    """JSON形式（配列形式 / 1行1JSON形式）をパースする"""
    ip_logs = {}
    raw_text = file.getvalue().decode("utf-8", errors="ignore").strip()
    if not raw_text:
        return ip_logs

    # 通常のJSON配列か、1行ずつのJSON(JSONL)かを自動判別して読み込み
    try:
        data = json.loads(raw_text)
        if isinstance(data, dict):
            data = [data]
    except json.JSONDecodeError:
        data = []
        for line in raw_text.split("\n"):
            if line.strip():
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    for item in data:
        if not isinstance(item, dict):
            continue

        ip = item.get("ip") or item.get("id.orig_h")
        if not ip:
            continue

        raw_time = item.get("timestamp") or item.get("ts")
        if not raw_time:
            continue
        try:
            if isinstance(raw_time, (int, float)) or str(raw_time).replace(
                ".", "", 1
            ).isdigit():
                dt = datetime.fromtimestamp(float(raw_time))
            else:
                dt = pd.to_datetime(raw_time).to_pydatetime()
        except Exception:
            continue

        # URL（Zeek由来の場合は接続先IP:ポートで代用）
        if "url" in item:
            url = str(item["url"])
        elif "id.resp_h" in item:
            url = f"{item.get('id.resp_h', '-')}:{item.get('id.resp_p', '-')}"
        else:
            url = "/"

        # ステータスコード
        raw_status = item.get("status", 200)
        status = int(raw_status) if str(raw_status).isdigit() else 200

        # バイト数
        raw_bytes = item.get("bytes", item.get("resp_ip_bytes", 0))
        b_val = int(raw_bytes) if str(raw_bytes).isdigit() else 0

        ip_logs.setdefault(
            str(ip), {"timestamps": [], "statuses": [], "urls": [], "bytes": []}
        )
        ip_logs[str(ip)]["timestamps"].append(dt)
        ip_logs[str(ip)]["statuses"].append(status)
        ip_logs[str(ip)]["urls"].append(url)
        ip_logs[str(ip)]["bytes"].append(b_val)

    return ip_logs


def parse_zeek_log(lines):
    """Zeek (旧Bro) 形式のログをパースする"""
    ip_logs = {}
    fields = []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not fields:
            continue

        cols = line.split("\t")
        if len(cols) < len(fields):
            continue

        row = dict(zip(fields, cols))
        try:
            dt = datetime.fromtimestamp(float(row.get("ts", 0)))
        except ValueError:
            continue

        ip = row.get("id.orig_h", "").strip()
        if not ip or ip == "-":
            continue

        resp_h = row.get("id.resp_h", "-")
        resp_p = row.get("id.resp_p", "-")
        target = f"{resp_h}:{resp_p}"

        conn_state = row.get("conn_state", "SF")
        failed_states = {"S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH"}
        status = 400 if conn_state in failed_states else 200

        raw_bytes = row.get("resp_ip_bytes", row.get("resp_bytes", "0"))
        b_val = int(raw_bytes) if raw_bytes.isdigit() else 0

        ip_logs.setdefault(
            ip, {"timestamps": [], "statuses": [], "urls": [], "bytes": []}
        )
        ip_logs[ip]["timestamps"].append(dt)
        ip_logs[ip]["statuses"].append(status)
        ip_logs[ip]["urls"].append(target)
        ip_logs[ip]["bytes"].append(b_val)

    return ip_logs


def extract_from_web_line(line):
    """通常のWebアクセスログ1行から各要素を抽出する"""
    ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
    if not ip_match:
        return None
    ip = ip_match.group(1)

    dt = None
    m_apache = re.search(r"(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})", line)
    m_iso = re.search(r"(\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2})", line)

    if m_apache:
        try:
            dt = datetime.strptime(m_apache.group(1), "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            pass
    elif m_iso:
        raw_t = m_iso.group(1).replace("/", "-").replace("T", " ")
        try:
            dt = datetime.strptime(raw_t, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    if not dt:
        return None

    url_match = re.search(
        r"\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)",
        line,
        re.IGNORECASE,
    )
    if url_match:
        url = url_match.group(1)
    else:
        path_match = re.search(r"\s(/\S*)", line)
        url = path_match.group(1) if path_match else "/"

    sb_match = re.search(r'\s([1-5]\d{2})(?:\s+(\d+|-))?(?:\s|"|$)', line)
    if sb_match:
        status = int(sb_match.group(1))
        b_raw = sb_match.group(2)
        b_val = int(b_raw) if (b_raw and b_raw.isdigit()) else 0
    else:
        status = 200
        b_val = 0

    return ip, dt, status, url, b_val


def parse_log_data(file):
    """LOG / TXT / CSV / JSON / Zeekログ の自動判別パース処理"""
    ip_logs = {}
    failed_samples = []

    # 1. JSON形式
    if file.name.endswith(".json"):
        ip_logs = parse_json_log(file)
        return ip_logs, failed_samples

    # 2. 表形式CSVとして読み込みを試行
    if file.name.endswith(".csv"):
        try:
            df = pd.read_csv(file)
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
                df["parsed_dt"] = pd.to_datetime(df[time_col], errors="coerce")
                valid_df = df.dropna(subset=["parsed_dt"])

                for ip, group in valid_df.groupby(ip_col):
                    ip_str = str(ip).strip()
                    ip_logs[ip_str] = {
                        "timestamps": group["parsed_dt"].tolist(),
                        "statuses": (
                            group[status_col].fillna(200).astype(int).tolist()
                            if status_col
                            else [200] * len(group)
                        ),
                        "urls": (
                            group[url_col].fillna("/").astype(str).tolist()
                            if url_col
                            else ["/"] * len(group)
                        ),
                        "bytes": (
                            group[bytes_col].fillna(0).astype(int).tolist()
                            if bytes_col
                            else [0] * len(group)
                        ),
                    }
                if ip_logs:
                    return ip_logs, failed_samples
        except Exception:
            pass

    file.seek(0)
    log_text = file.getvalue().decode("utf-8", errors="ignore")
    lines = log_text.strip().split("\n")

    # 3. Zeek形式
    if any(line.startswith("#fields") for line in lines[:20]):
        ip_logs = parse_zeek_log(lines)
        return ip_logs, failed_samples

    # 4. 通常のWebアクセスログ形式
    for line in lines:
        if not line.strip():
            continue
        parsed = extract_from_web_line(line)
        if parsed:
            ip, dt, status, url, b_val = parsed
            ip_logs.setdefault(
                ip, {"timestamps": [], "statuses": [], "urls": [], "bytes": []}
            )
            ip_logs[ip]["timestamps"].append(dt)
            ip_logs[ip]["statuses"].append(status)
            ip_logs[ip]["urls"].append(url)
            ip_logs[ip]["bytes"].append(b_val)
        else:
            if len(failed_samples) < 3:
                failed_samples.append(line.strip())

    return ip_logs, failed_samples


if uploaded_file is not None:
    ip_logs, failed_samples = parse_log_data(uploaded_file)

    if not ip_logs:
        st.error("⚠️ ログ解析に失敗しました。対応していない書式です。")
        if failed_samples:
            st.warning("▼ 読み込めなかった行のサンプル（最初の3行）：")
            for sample in failed_samples:
                st.code(sample, language="text")
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
        "👈 左側のサイドバーからアクセスログファイル（.log / .txt / .csv / .json）を選んでアップロードしてください。"
    )
