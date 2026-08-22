"""
Module 6 — Dashboard components

Small, reusable Streamlit UI helpers, kept deliberately restrained:
no gradients, no glow, no emoji-heavy badges — just a clean, readable
internal-tool look.
"""

import streamlit as st

SEVERITY_COLORS = {
    "Low": "#5b7fa6",
    "Medium": "#b8860b",
    "High": "#c0392b",
    "Critical": "#7b1113",
}

STATUS_COLORS = {
    "New": "#8a8a8a",
    "Investigating": "#b8860b",
    "Resolved": "#2f6b3a",
}


def inject_base_css():
    st.markdown(
        """
        <style>
        .metric-card {
            border: 1px solid #d9d9d9;
            border-radius: 4px;
            padding: 14px 16px;
            background-color: #ffffff;
        }
        .metric-label {
            font-size: 0.78rem;
            color: #666666;
            text-transform: uppercase;
            letter-spacing: 0.03em;
            margin-bottom: 4px;
        }
        .metric-value {
            font-size: 1.6rem;
            font-weight: 600;
            color: #1a1a1a;
        }
        .section-header {
            font-size: 1.0rem;
            font-weight: 600;
            color: #1a1a1a;
            border-bottom: 1px solid #e0e0e0;
            padding-bottom: 6px;
            margin-top: 8px;
            margin-bottom: 10px;
        }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label, value):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_header(text):
    st.markdown(f'<div class="section-header">{text}</div>', unsafe_allow_html=True)


def severity_badge(severity):
    color = SEVERITY_COLORS.get(severity, "#666666")
    return f'<span class="badge" style="background-color:{color};">{severity}</span>'


def status_badge(status):
    color = STATUS_COLORS.get(status, "#666666")
    return f'<span class="badge" style="background-color:{color};">{status}</span>'
