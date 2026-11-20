# app.py - 省メモリ・ストリーミング読み込み & Honeypot JSON対応版
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
max_lines = st.sidebar.number_input(
    "最大読み込み行数（メモリ保護用）",
    min_value=1000,
    max_value=500000,
    value=100000,
    step=10000,
)


def extract_json_record(item, ip_logs):
    """1件のJSON辞書からIP・日時・URL・ステータス・バイト数を抽出して追加する"""
    if not isinstance(item, dict):
        return

    # payload が入れ子（文字列または辞書）になっている場合は中身を展開して統合
    merged = dict(item)
    payload = item.get("payload")
    if isinstance(payload, str):
        try:
            parsed_payload = json.loads(payload)
            if isinstance(parsed_payload, dict):
                merged.update(parsed_payload)
        except json.JSONDecodeError:
            pass
    elif isinstance(payload, dict):
        merged.update(payload)

    # 1. IPアドレス（Webログ / Honeypot / Zeek の各種キーに対応）
    ip = (
        merged.get("ip")
        or merged.get("src_ip")
        or merged.get("peerIP")
        or merged.get("attackerIP")
        or merged.get("remote_ip")
        or merged.get("id.orig_h")
    )
    if not ip:
        return
    ip = str(ip).strip()

    # 2. 日時（{"$date": "..."} 形式・UNIX秒・ミリ秒・ISO文字列に対応）
    raw_time = (
        merged.get("timestamp")
        or merged.get("ts")
        or merged.get("@timestamp")
        or merged.get("time")
    )
    if isinstance(raw_time, dict):
        raw_time = raw_time.get("$date")
    if not raw_time:
        return

    try:
        if isinstance(raw_time, (int, float)) or str(raw_time).replace(
            ".", "", 1
        ).isdigit():
            ts_val = float(raw_time)
            if ts_val > 1e11:  # ミリ秒単位の場合は秒に変換
                ts_val /= 1000.0
            dt = datetime.fromtimestamp(ts_val)
        else:
            dt = pd.to_datetime(raw_time).to_pydatetime()
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        
    except Exception:
        return

    # 3. URL / アクセス対象（URLがない場合はイベント名や宛先ポートで代用）
    if merged.get("url"):
        url = str(merged["url"])
    elif merged.get("request_url"):
        url = str(merged["request_url"])
    elif merged.get("path"):
        url = str(merged["path"])
    elif merged.get("eventid"):
        url = str(merged["eventid"])
    elif merged.get("id.resp_h"):
        url = f"{merged.get('id.resp_h')}:{merged.get('id.resp_p', '-')}"
    elif merged.get("dst_port") or merged.get("hostPort"):
        url = f"port:{merged.get('dst_port') or merged.get('hostPort')}"
    else:
        url = "/"

    # 4. ステータスコード（ログイン失敗などのイベントは400扱いに変換）
    raw_status = merged.get("status") or merged.get("status_code")
    if raw_status is not None and str(raw_status).isdigit():
        status = int(raw_status)
    elif any(
        k in str(merged.get("eventid", "")).lower()
        for k in ["failed", "error", "closed"]
    ):
        status = 400
    else:
        status = 200

    # 5. バイト数
    raw_bytes = (
        merged.get("bytes")
        or merged.get("resp_ip_bytes")
        or merged.get("size")
        or 0
    )
    b_val = int(raw_bytes) if str(raw_bytes).isdigit() else 0

    ip_logs.setdefault(
        ip, {"timestamps": [], "statuses": [], "urls": [], "bytes": []}
    )
    ip_logs[ip]["timestamps"].append(dt)
    ip_logs[ip]["statuses"].append(status)
    ip_logs[ip]["urls"].append(url)
    ip_logs[ip]["bytes"].append(b_val)


def parse_json_log(file, limit):
    """JSONファイルを1行ずつストリーミング読み込み（省メモリ版）"""
    ip_logs = {}
    file.seek(0)
    head = file.read(512).decode("utf-8", errors="ignore").lstrip()
    file.seek(0)

    # 配列形式 ([{...}, {...}]) の場合
    if head.startswith("["):
        try:
            data = json.load(file)
            for item in data[:limit]:
                extract_json_record(item, ip_logs)
        except Exception:
            pass
        return ip_logs

    # 1行1JSON形式 (JSON Lines / honeypot.json) の場合：全量をメモリに載せず1行ずつ処理
    for idx, raw_line in enumerate(file):
        if idx >= limit:
            break
        line = raw_line.decode("utf-8", errors="ignore").strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            extract_json_record(item, ip_logs)
        except json.JSONDecodeError:
            continue

    return ip_logs


def parse_zeek_log(file, limit):
    """Zeek (旧Bro) 形式のログを1行ずつパースする"""
    ip_logs = {}
    fields = []
    file.seek(0)

    for idx, raw_line in enumerate(file):
        if idx >= limit:
            break
        line = raw_line.decode("utf-8", errors="ignore").strip()
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


def parse_log_data(file, limit):
    """LOG / TXT / CSV / JSON / Zeekログ の自動判別パース処理"""
    ip_logs = {}
    failed_samples = []

    if file.name.endswith(".json"):
        ip_logs = parse_json_log(file, limit)
        return ip_logs, failed_samples

    if file.name.endswith(".csv"):
        try:
            df = pd.read_csv(file, nrows=limit)
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
    head_lines = [
        file.readline().decode("utf-8", errors="ignore") for _ in range(20)
    ]
    if any(line.startswith("#fields") for line in head_lines):
        ip_logs = parse_zeek_log(file, limit)
        return ip_logs, failed_samples

    file.seek(0)
    for idx, raw_line in enumerate(file):
        if idx >= limit:
            break
        line = raw_line.decode("utf-8", errors="ignore").strip()
        if not line:
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
                failed_samples.append(line)

    return ip_logs, failed_samples


if uploaded_file is not None:
    ip_logs, failed_samples = parse_log_data(uploaded_file, max_lines)

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
