"""
Module 6 — Dashboard charts

Plotly figures, styled to look like a restrained enterprise tool: no
neon colors, minimal chrome, a single muted accent palette.
"""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

MUTED_PALETTE = ["#3b5a7a", "#5b7fa6", "#8ba3bd", "#b8860b", "#c0392b", "#7b1113"]

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
SEVERITY_COLORS = {
    "Low": "#5b7fa6",
    "Medium": "#b8860b",
    "High": "#c0392b",
    "Critical": "#7b1113",
}


def _base_layout(fig, height=300):
    fig.update_layout(
        height=height,
        margin=dict(l=10, r=10, t=30, b=10),
        plot_bgcolor="white",
        paper_bgcolor="white",
        font=dict(family="Arial, sans-serif", size=12, color="#333333"),
        showlegend=False,
    )
    return fig


def event_timeline_chart(events_df):
    if events_df.empty:
        return go.Figure()
    df = events_df.copy()
    df["bucket"] = pd.to_datetime(df["timestamp"]).dt.floor("15min")
    counts = df.groupby("bucket").size().reset_index(name="count")
    fig = px.line(counts, x="bucket", y="count")
    fig.update_traces(line_color="#3b5a7a", line_width=2)
    fig.update_xaxes(title=None)
    fig.update_yaxes(title="Events")
    return _base_layout(fig)


def threat_distribution_chart(alerts_df):
    if alerts_df.empty:
        return go.Figure()
    counts = alerts_df["severity"].value_counts().reindex(SEVERITY_ORDER).fillna(0).reset_index()
    counts.columns = ["severity", "count"]
    fig = px.bar(counts, x="severity", y="count", color="severity",
                 color_discrete_map=SEVERITY_COLORS)
    fig.update_xaxes(title=None)
    fig.update_yaxes(title="Alerts")
    return _base_layout(fig)


def threat_types_chart(alerts_df):
    if alerts_df.empty:
        return go.Figure()
    counts = alerts_df["threat_type"].value_counts().reset_index()
    counts.columns = ["threat_type", "count"]
    fig = px.bar(counts, x="count", y="threat_type", orientation="h",
                 color_discrete_sequence=["#3b5a7a"])
    fig.update_yaxes(title=None)
    fig.update_xaxes(title="Alerts")
    return _base_layout(fig, height=280)
