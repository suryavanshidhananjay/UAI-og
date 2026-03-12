"""
╔══════════════════════════════════════════════════════════════╗
║  styles.py — CYBERGUARD UI Theme                             ║
║  Professional Cybersecurity Dashboard                        ║
╚══════════════════════════════════════════════════════════════╝
"""
import streamlit as st


# ══════════════════════════════════════════════════════════════
# CYBERGUARD THEME CSS
# ══════════════════════════════════════════════════════════════

CYBERGUARD_CSS = """
<style>
    /* ══════════════════════════════════════════════════════════
       FONTS
       ══════════════════════════════════════════════════════════ */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        color: #e2e8f0;
    }

    /* ══════════════════════════════════════════════════════════
       MAIN BACKGROUND — Deep Navy/Dark
       ══════════════════════════════════════════════════════════ */
    .stApp {
        background: #0b1120;
    }

    /* ══════════════════════════════════════════════════════════
       SIDEBAR — Dark with teal accent
       ══════════════════════════════════════════════════════════ */
    section[data-testid="stSidebar"] {
        background: #0f1629 !important;
        border-right: 1px solid #1e293b;
        padding-top: 0 !important;
    }
    section[data-testid="stSidebar"] > div:first-child {
        padding-top: 0 !important;
    }
    
    /* Sidebar navigation items */
    section[data-testid="stSidebar"] .stRadio label {
        color: #94a3b8 !important;
        font-size: 0.9rem;
        font-weight: 500;
        padding: 12px 16px;
        border-radius: 8px;
        transition: all 0.2s ease;
        display: flex;
        align-items: center;
        gap: 12px;
        margin: 2px 8px;
    }
    section[data-testid="stSidebar"] .stRadio label:hover {
        color: #e2e8f0 !important;
        background: rgba(34, 211, 238, 0.08) !important;
    }
    section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label[data-baseweb="radio"] {
        padding: 12px 16px !important;
        border-radius: 8px;
        margin: 2px 0;
    }
    
    /* Active nav item */
    section[data-testid="stSidebar"] .stRadio div[data-checked="true"] label {
        background: linear-gradient(90deg, rgba(34, 211, 238, 0.15) 0%, transparent 100%) !important;
        color: #22d3ee !important;
        border-left: 3px solid #22d3ee;
    }

    /* Hide radio circles */
    section[data-testid="stSidebar"] .stRadio [data-testid="stMarkdownContainer"] {
        display: flex;
        align-items: center;
    }
    
    /* Sidebar toggle */
    button[data-testid="stSidebarCollapseButton"],
    button[data-testid="stSidebarCollapsedControl"] {
        color: #64748b !important;
        background: transparent !important;
    }

    /* ══════════════════════════════════════════════════════════
       CARDS — Dark panels with subtle borders
       ══════════════════════════════════════════════════════════ */
    .cyber-card {
        background: #111827;
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 16px;
    }
    .cyber-card-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 12px;
    }
    .cyber-card-title {
        color: #e2e8f0;
        font-weight: 600;
        font-size: 1rem;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .cyber-card-badge {
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 500;
    }
    .badge-fair {
        background: rgba(251, 146, 60, 0.2);
        color: #fb923c;
    }
    .badge-good {
        background: rgba(34, 197, 94, 0.2);
        color: #22c55e;
    }
    .badge-critical {
        background: rgba(239, 68, 68, 0.2);
        color: #ef4444;
    }

    /* ══════════════════════════════════════════════════════════
       METRIC CARDS — Large numbers
       ══════════════════════════════════════════════════════════ */
    .metric-card {
        background: #111827;
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 20px 24px;
    }
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        color: #e2e8f0;
        line-height: 1;
    }
    .metric-value-teal { color: #22d3ee; }
    .metric-value-green { color: #22c55e; }
    .metric-value-orange { color: #fb923c; }
    .metric-value-red { color: #ef4444; }
    .metric-label {
        font-size: 0.85rem;
        color: #64748b;
        margin-top: 4px;
    }

    /* ══════════════════════════════════════════════════════════
       SUMMARY CARDS — Icon + stats
       ══════════════════════════════════════════════════════════ */
    .summary-card {
        background: #111827;
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 16px 20px;
        display: flex;
        flex-direction: column;
        gap: 8px;
    }
    .summary-icon {
        width: 36px;
        height: 36px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.1rem;
    }
    .summary-icon-purple { background: rgba(139, 92, 246, 0.2); color: #a78bfa; }
    .summary-icon-blue { background: rgba(59, 130, 246, 0.2); color: #60a5fa; }
    .summary-icon-teal { background: rgba(34, 211, 238, 0.2); color: #22d3ee; }
    .summary-icon-orange { background: rgba(251, 146, 60, 0.2); color: #fb923c; }
    .summary-icon-red { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
    .summary-icon-green { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
    .summary-stat {
        font-size: 1.1rem;
        font-weight: 600;
    }
    .summary-stat-orange { color: #fb923c; }
    .summary-stat-teal { color: #22d3ee; }
    .summary-stat-red { color: #ef4444; }
    .summary-stat-green { color: #22c55e; }
    .summary-desc {
        font-size: 0.8rem;
        color: #64748b;
    }
    .summary-label {
        font-size: 0.85rem;
        color: #94a3b8;
        margin-top: auto;
    }

    /* ══════════════════════════════════════════════════════════
       PROGRESS BARS
       ══════════════════════════════════════════════════════════ */
    .progress-container {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .progress-icon {
        font-size: 1rem;
        color: #64748b;
    }
    .progress-label {
        color: #94a3b8;
        font-size: 0.9rem;
        min-width: 80px;
    }
    .progress-bar-bg {
        flex: 1;
        height: 8px;
        background: #1e293b;
        border-radius: 4px;
        overflow: hidden;
    }
    .progress-bar-fill {
        height: 100%;
        border-radius: 4px;
        transition: width 0.5s ease;
    }
    .progress-fill-teal { background: linear-gradient(90deg, #0891b2, #22d3ee); }
    .progress-fill-green { background: linear-gradient(90deg, #16a34a, #22c55e); }
    .progress-fill-orange { background: linear-gradient(90deg, #ea580c, #fb923c); }
    .progress-fill-red { background: linear-gradient(90deg, #dc2626, #ef4444); }
    .progress-value {
        color: #e2e8f0;
        font-weight: 600;
        font-size: 0.9rem;
        min-width: 45px;
        text-align: right;
    }

    /* ══════════════════════════════════════════════════════════
       DONUT CHART (Security Score)
       ══════════════════════════════════════════════════════════ */
    .donut-container {
        display: flex;
        align-items: center;
        gap: 24px;
    }
    .donut-chart {
        position: relative;
        width: 120px;
        height: 120px;
    }
    .donut-ring {
        width: 100%;
        height: 100%;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .donut-center {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        text-align: center;
    }
    .donut-score {
        font-size: 2rem;
        font-weight: 700;
        color: #e2e8f0;
    }
    .donut-label {
        font-size: 0.75rem;
        color: #64748b;
    }
    .score-bars {
        flex: 1;
    }
    .score-bar-row {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 8px;
    }
    .score-bar-label {
        color: #94a3b8;
        font-size: 0.85rem;
        width: 70px;
    }
    .score-bar-track {
        flex: 1;
        height: 6px;
        background: #1e293b;
        border-radius: 3px;
        overflow: hidden;
    }
    .score-bar-fill-green { background: #22c55e; }
    .score-bar-fill-orange { background: #fb923c; }
    .score-bar-fill-red { background: #ef4444; }
    .score-bar-value {
        color: #e2e8f0;
        font-size: 0.85rem;
        font-weight: 500;
        width: 40px;
        text-align: right;
    }

    /* ══════════════════════════════════════════════════════════
       ALERTS LIST
       ══════════════════════════════════════════════════════════ */
    .alert-item {
        display: flex;
        align-items: flex-start;
        gap: 12px;
        padding: 12px 0;
        border-bottom: 1px solid #1e293b;
    }
    .alert-item:last-child {
        border-bottom: none;
    }
    .alert-icon {
        width: 24px;
        height: 24px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.75rem;
        flex-shrink: 0;
        margin-top: 2px;
    }
    .alert-icon-red { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
    .alert-icon-orange { background: rgba(251, 146, 60, 0.2); color: #fb923c; }
    .alert-icon-teal { background: rgba(34, 211, 238, 0.2); color: #22d3ee; }
    .alert-icon-green { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
    .alert-content {
        flex: 1;
    }
    .alert-title {
        color: #e2e8f0;
        font-size: 0.9rem;
        font-weight: 500;
    }
    .alert-meta {
        color: #64748b;
        font-size: 0.8rem;
        margin-top: 2px;
    }

    /* ══════════════════════════════════════════════════════════
       STATUS BADGES
       ══════════════════════════════════════════════════════════ */
    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 500;
    }
    .status-intact { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
    .status-modified { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
    .status-new { background: rgba(251, 146, 60, 0.15); color: #fb923c; }
    .status-info { background: rgba(59, 130, 246, 0.15); color: #60a5fa; }
    .status-warning { background: rgba(251, 146, 60, 0.15); color: #fb923c; }
    .status-critical { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
    
    .type-badge {
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 500;
    }
    .type-system { background: rgba(59, 130, 246, 0.2); color: #60a5fa; }
    .type-config { background: rgba(139, 92, 246, 0.2); color: #a78bfa; }
    .type-startup { background: rgba(251, 146, 60, 0.2); color: #fb923c; }
    
    .risk-low { color: #22c55e; }
    .risk-medium { color: #fb923c; }
    .risk-high { color: #ef4444; }

    /* ══════════════════════════════════════════════════════════
       FILTER TABS
       ══════════════════════════════════════════════════════════ */
    .filter-tabs {
        display: flex;
        gap: 8px;
        margin-bottom: 16px;
        flex-wrap: wrap;
    }
    .filter-tab {
        padding: 6px 14px;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s ease;
        border: 1px solid #1e293b;
        background: transparent;
        color: #94a3b8;
    }
    .filter-tab:hover {
        border-color: #334155;
        color: #e2e8f0;
    }
    .filter-tab-active {
        background: #22d3ee;
        border-color: #22d3ee;
        color: #0b1120;
    }

    /* ══════════════════════════════════════════════════════════
       BUTTONS
       ══════════════════════════════════════════════════════════ */
    .stButton > button {
        background: linear-gradient(135deg, #0891b2 0%, #22d3ee 100%);
        color: #0b1120;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        padding: 10px 20px;
        transition: all 0.2s ease;
    }
    .stButton > button:hover {
        box-shadow: 0 4px 16px rgba(34, 211, 238, 0.3);
        transform: translateY(-1px);
    }
    
    .btn-outline {
        background: transparent !important;
        border: 1px solid #334155 !important;
        color: #94a3b8 !important;
    }
    .btn-outline:hover {
        border-color: #22d3ee !important;
        color: #22d3ee !important;
    }
    
    .btn-danger {
        background: #ef4444 !important;
        color: white !important;
    }

    /* ══════════════════════════════════════════════════════════
       TABLE STYLES
       ══════════════════════════════════════════════════════════ */
    .data-table {
        width: 100%;
        border-collapse: collapse;
    }
    .data-table th {
        text-align: left;
        padding: 12px 16px;
        color: #64748b;
        font-weight: 500;
        font-size: 0.85rem;
        border-bottom: 1px solid #1e293b;
    }
    .data-table td {
        padding: 12px 16px;
        color: #e2e8f0;
        font-size: 0.9rem;
        border-bottom: 1px solid #1e293b;
    }
    .data-table tr:hover {
        background: rgba(34, 211, 238, 0.03);
    }

    /* ══════════════════════════════════════════════════════════
       INPUTS
       ══════════════════════════════════════════════════════════ */
    .stTextInput > div > div > input {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        color: #e2e8f0;
        padding: 10px 14px;
    }
    .stTextInput > div > div > input:focus {
        border-color: #22d3ee;
        box-shadow: 0 0 0 2px rgba(34, 211, 238, 0.2);
    }

    /* ══════════════════════════════════════════════════════════
       HEADER BAR
       ══════════════════════════════════════════════════════════ */
    .header-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 0;
        margin-bottom: 24px;
    }
    .header-title {
        color: #e2e8f0;
        font-size: 1.5rem;
        font-weight: 600;
    }
    .header-subtitle {
        color: #64748b;
        font-size: 0.9rem;
    }
    .header-actions {
        display: flex;
        align-items: center;
        gap: 16px;
    }
    .quick-scan-btn {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 16px;
        background: #111827;
        border: 1px solid #334155;
        border-radius: 8px;
        color: #e2e8f0;
        font-size: 0.9rem;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s ease;
    }
    .quick-scan-btn:hover {
        border-color: #22d3ee;
        color: #22d3ee;
    }

    /* ══════════════════════════════════════════════════════════
       SYSTEM STATUS BADGE
       ══════════════════════════════════════════════════════════ */
    .system-status {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 8px 14px;
        background: rgba(34, 197, 94, 0.15);
        border: 1px solid rgba(34, 197, 94, 0.3);
        border-radius: 8px;
        margin: 16px;
    }
    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #22c55e;
        box-shadow: 0 0 8px rgba(34, 197, 94, 0.5);
        animation: pulse 2s infinite;
    }
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    .status-text {
        color: #22c55e;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .status-time {
        color: #64748b;
        font-size: 0.8rem;
    }

    /* ══════════════════════════════════════════════════════════
       HIDE STREAMLIT BRANDING
       ══════════════════════════════════════════════════════════ */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* ══════════════════════════════════════════════════════════
       SCROLLBAR
       ══════════════════════════════════════════════════════════ */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #0b1120; }
    ::-webkit-scrollbar-thumb {
        background: #334155;
        border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover { background: #475569; }

    /* ══════════════════════════════════════════════════════════
       LIVE MONITORING INDICATOR
       ══════════════════════════════════════════════════════════ */
    .live-indicator {
        display: flex;
        align-items: center;
        gap: 6px;
        color: #64748b;
        font-size: 0.85rem;
    }
    .live-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: #22c55e;
        animation: pulse 1.5s infinite;
    }

    /* ══════════════════════════════════════════════════════════
       SUSPICIOUS SOURCES PANEL
       ══════════════════════════════════════════════════════════ */
    .suspicious-item {
        background: #1e293b;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 12px;
    }
    .suspicious-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 8px;
    }
    .suspicious-ip {
        color: #ef4444;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }
    .suspicious-count {
        color: #ef4444;
        font-size: 0.85rem;
    }
    .suspicious-target {
        color: #94a3b8;
        font-size: 0.85rem;
        margin-bottom: 10px;
    }
    .suspicious-actions {
        display: flex;
        gap: 8px;
    }
    .action-btn {
        padding: 6px 12px;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s ease;
    }
    .action-btn-danger {
        background: #ef4444;
        color: white;
        border: none;
    }
    .action-btn-outline {
        background: transparent;
        border: 1px solid #334155;
        color: #94a3b8;
    }
    .action-btn-outline:hover {
        border-color: #22d3ee;
        color: #22d3ee;
    }
</style>
"""


def apply_styles():
    """Inject the CYBERGUARD CSS theme."""
    st.markdown(CYBERGUARD_CSS, unsafe_allow_html=True)


def metric_card(value, label, color="white"):
    """Render a large metric card."""
    color_class = f"metric-value-{color}" if color != "white" else "metric-value"
    return f'''
        <div class="metric-card">
            <div class="{color_class}">{value}</div>
            <div class="metric-label">{label}</div>
        </div>
    '''


def summary_card(icon, icon_color, stat, stat_color, desc, label):
    """Render a summary card with icon and stats."""
    return f'''
        <div class="summary-card">
            <div class="summary-icon summary-icon-{icon_color}">{icon}</div>
            <div class="summary-stat summary-stat-{stat_color}">{stat}</div>
            <div class="summary-desc">{desc}</div>
            <div class="summary-label">{label}</div>
        </div>
    '''


def progress_bar(icon, label, value, max_val=100, color="teal"):
    """Render a progress bar with icon and label."""
    pct = min(100, int((value / max_val) * 100))
    return f'''
        <div class="progress-container">
            <span class="progress-icon">{icon}</span>
            <span class="progress-label">{label}</span>
            <div class="progress-bar-bg">
                <div class="progress-bar-fill progress-fill-{color}" style="width: {pct}%;"></div>
            </div>
            <span class="progress-value">{value}%</span>
        </div>
    '''


def security_score_donut(score, safe_pct, warn_pct, crit_pct):
    """Render the security score donut chart."""
    # Determine color based on score
    if score >= 80:
        ring_color = "#22c55e"
        status = "Good"
    elif score >= 50:
        ring_color = "#fb923c"
        status = "Fair"
    else:
        ring_color = "#ef4444"
        status = "Critical"
    
    return f'''
        <div class="donut-container">
            <div class="donut-chart">
                <div class="donut-ring" style="background: conic-gradient({ring_color} {score}%, #1e293b {score}%);">
                </div>
                <div class="donut-center" style="background: #111827; width: 80px; height: 80px; border-radius: 50%;">
                    <div class="donut-score">{score}</div>
                    <div class="donut-label">{status}</div>
                </div>
            </div>
            <div class="score-bars">
                <div class="score-bar-row">
                    <span class="score-bar-label">Safe</span>
                    <div class="score-bar-track">
                        <div class="score-bar-fill-green" style="width: {safe_pct}%; height: 100%; border-radius: 3px;"></div>
                    </div>
                    <span class="score-bar-value">{safe_pct}%</span>
                </div>
                <div class="score-bar-row">
                    <span class="score-bar-label">Warnings</span>
                    <div class="score-bar-track">
                        <div class="score-bar-fill-orange" style="width: {warn_pct}%; height: 100%; border-radius: 3px;"></div>
                    </div>
                    <span class="score-bar-value">{warn_pct}%</span>
                </div>
                <div class="score-bar-row">
                    <span class="score-bar-label">Critical</span>
                    <div class="score-bar-track">
                        <div class="score-bar-fill-red" style="width: {crit_pct}%; height: 100%; border-radius: 3px;"></div>
                    </div>
                    <span class="score-bar-value">{crit_pct}%</span>
                </div>
            </div>
        </div>
    '''


def alert_item(icon_type, title, meta):
    """Render an alert list item without leading whitespace to avoid markdown code blocks."""
    return (
        f'<div class="alert-item">'
        f'<div class="alert-icon alert-icon-{icon_type}">●</div>'
        f'<div class="alert-content">'
        f'<div class="alert-title">{title}</div>'
        f'<div class="alert-meta">{meta}</div>'
        f'</div>'
        f'</div>'
    )


def neon_divider():
    """Render a subtle divider."""
    st.markdown('<div style="height:1px;background:#1e293b;margin:20px 0;"></div>', unsafe_allow_html=True)


