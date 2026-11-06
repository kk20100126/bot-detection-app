from datetime import datetime
import numpy as np
import pandas as pd


def test_macro_error_rate(statuses, p_error_base=0.1):
    """[Node 1] 二項分布による大量エラー検知"""
    n_total = len(statuses)
    n_errors = sum(1 for s in statuses if s in [400, 401, 403, 404])
    threshold_K = (n_total * p_error_base) + (
        3 * np.sqrt(n_total * p_error_base * (1 - p_error_base))
    )
    return n_errors > threshold_K


def test_micro_zscore(
    timestamps, epsilon_candidates=[0.2, 0.5, 1.0, 2.0, 4.0]
):
    """[Node 2] マルチスケール Z-score による隠蔽周期通信検知"""
    timestamps_sorted = sorted(timestamps)
    intervals = [
        (timestamps_sorted[i] - timestamps_sorted[i - 1]).total_seconds()
        for i in range(1, len(timestamps_sorted))
    ]
    if len(intervals) < 2:
        return False, 0.0

    L = max(intervals) - min(intervals) or 100.0
    m = len(intervals)
    intervals_sorted = np.sort(intervals)
    max_z = 0.0

    for eps in epsilon_candidates:
        observed_X = sum(
            np.searchsorted(
                intervals_sorted, intervals_sorted[left] + eps, side="right"
            )
            - left
            - 1
            for left in range(m)
        )
        prob_collision = (2 * eps) / L
        expected_E = ((m * (m - 1)) / 2) * prob_collision

        if expected_E > 0:
            z = (observed_X - expected_E) / np.sqrt(expected_E)
            max_z = max(max_z, z)

    return max_z >= 3.0, round(max_z, 2)


def test_hhi_diversity(urls):
    """[Node 3] HHI指数によるアクセス先集中/偏向検知"""
    if not urls:
        return False, 0.0
    counts = pd.Series(urls).value_counts()
    hhi = ((counts / len(urls)) ** 2).sum()
    is_failed = (hhi > 0.8) or (hhi < 0.05 and len(counts) > 5)
    return is_failed, round(hhi, 2)


def test_byte_variance(bytes_list):
    """[Node 4] レスポンスバイト数の標準偏差検知"""
    if len(bytes_list) < 3:
        return False, 0.0
    std_bytes = np.std(bytes_list)
    return std_bytes < 5.0, round(std_bytes, 1)
