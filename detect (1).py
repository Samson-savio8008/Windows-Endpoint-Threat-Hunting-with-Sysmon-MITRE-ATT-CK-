"""
Windows endpoint threat hunting on real Sysmon / Security telemetry.

Data: 18 attack simulations from the OTRF Security-Datasets project (MIT licence).
Each scenario is one known ATT&CK technique run on a lab Windows host.

What this script does:
  1. Loads every event (Sysmon, Security, PowerShell, WMI) into one DataFrame
  2. Runs 17 Sigma-style detection rules, each mapped to MITRE ATT&CK
  3. Compares alerts against the scenario labels (scenarios.csv)
  4. Writes tables, a coverage heatmap and a summary with the numbers

Usage:  python download_data.py   (once)
        python detect.py
"""
import csv
import json
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

DATA_DIR = Path("data")
OUT_DIR = Path("results")

FIELDS = [
    "Channel", "EventID", "Hostname", "@timestamp", "Image", "CommandLine",
    "ParentImage", "ParentCommandLine", "User", "SourceImage", "TargetImage",
    "GrantedAccess", "TargetObject", "Details", "OriginalFileName", "TaskName",
    "UtcTime", "TimeCreated", "TargetFilename",
]


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------
def load_events() -> pd.DataFrame:
    rows = []
    for scen_dir in sorted(p for p in DATA_DIR.iterdir() if p.is_dir()):
        for f in scen_dir.glob("*.json"):
            with open(f, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    e = json.loads(line)
                    rec = {k: e.get(k) for k in FIELDS}
                    rec["scenario"] = scen_dir.name
                    rows.append(rec)
    df = pd.DataFrame(rows)
    df["EventID"] = pd.to_numeric(df["EventID"], errors="coerce")
    # Sysmon uses UtcTime; other channels use @timestamp / TimeCreated
    raw_ts = df["UtcTime"].fillna(df["@timestamp"]).fillna(df["TimeCreated"])
    df["ts"] = pd.to_datetime(raw_ts, errors="coerce", utc=True, format="mixed")
    df["is_sysmon"] = df["Channel"].astype(str).str.contains("Sysmon", case=False)
    for c in ["Image", "CommandLine", "ParentImage", "SourceImage", "TargetImage",
              "GrantedAccess", "TargetObject", "OriginalFileName", "TaskName", "TargetFilename"]:
        df[c] = df[c].fillna("").astype(str)
    return df


def contains(series, pattern):
    return series.str.contains(pattern, case=False, regex=True, na=False)


def basename(series):
    return series.str.replace("/", "\\", regex=False).str.split("\\").str[-1].str.lower()


# --------------------------------------------------------------------------
# Detection rules (Sigma-style logic written in pandas)
# Each rule: id, name, ATT&CK technique(s), tactic, function(df) -> bool mask
# --------------------------------------------------------------------------
def proc_create(df):
    return df["is_sysmon"] & (df["EventID"] == 1)


DUMP_MASKS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1f1fff", "0x1f3fff", "0x1fffff"}
SYSTEM_LSASS_READERS = {"svchost.exe", "csrss.exe", "wininit.exe", "lsm.exe", "services.exe",
                        "msmpeng.exe", "wmiprvse.exe", "winlogon.exe", "taskmgr.exe"}
SYSTEM_REMOTE_THREAD_SOURCES = {"csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
                                "svchost.exe", "winlogon.exe", "smss.exe", "wmiprvse.exe",
                                "system", "explorer.exe"}

RULES = [
    {"id": "R01", "name": "LSASS dump via comsvcs.dll MiniDump", "tech": ["T1003.001"],
     "tactic": "Credential Access",
     "fn": lambda d: proc_create(d) & contains(d["CommandLine"], r"comsvcs") & contains(d["CommandLine"], r"minidump")},
    {"id": "R02", "name": "LSASS opened with dump-capable access mask", "tech": ["T1003.001"],
     "tactic": "Credential Access",
     "fn": lambda d: d["is_sysmon"] & (d["EventID"] == 10)
     & d["TargetImage"].str.lower().str.endswith("lsass.exe")
     & d["GrantedAccess"].str.lower().isin(DUMP_MASKS)
     & ~basename(d["SourceImage"]).isin(SYSTEM_LSASS_READERS)},
    {"id": "R03", "name": "Registry hive export (SAM/SECURITY/SYSTEM) via reg.exe", "tech": ["T1003.002", "T1003.004"],
     "tactic": "Credential Access",
     "fn": lambda d: proc_create(d) & contains(d["CommandLine"], r"\breg(?:\.exe)?\"?\s+save\s+hklm\\(?:sam|security|system)")},
    {"id": "R04", "name": "esentutl copy from Volume Shadow Copy", "tech": ["T1003.002"],
     "tactic": "Credential Access",
     "fn": lambda d: proc_create(d) & contains(d["CommandLine"], r"esentutl") & contains(d["CommandLine"], r"/vss")},
    {"id": "R05", "name": "mshta executing script or remote content", "tech": ["T1218.005"],
     "tactic": "Defense Evasion",
     "fn": lambda d: proc_create(d) & contains(d["CommandLine"], r"\bmshta(?:\.exe)?\b.*(?:vbscript:|javascript:|https?://|\.hta)")},
    {"id": "R06", "name": "cmstp silent INF install", "tech": ["T1218.003"],
     "tactic": "Defense Evasion",
     "fn": lambda d: proc_create(d) & contains(d["CommandLine"], r"\bcmstp(?:\.exe)?\"?\s.*/(?:s|au)\b")},
    {"id": "R07", "name": "InstallUtil used to run a payload", "tech": ["T1218.004"],
     "tactic": "Defense Evasion",
     "fn": lambda d: proc_create(d) & contains(d["CommandLine"], r"installutil(?:\.exe)?.*(?:/u\b|/logfile=)")},
    {"id": "R08", "name": "bitsadmin file transfer", "tech": ["T1197"],
     "tactic": "Persistence / Defense Evasion",
     "fn": lambda d: proc_create(d) & contains(d["CommandLine"], r"bitsadmin(?:\.exe)?\s.*/(?:transfer|addfile)")},
    {"id": "R09", "name": "Firewall rule added to allow inbound traffic", "tech": ["T1562.004"],
     "tactic": "Defense Evasion",
     "fn": lambda d: proc_create(d) & contains(d["CommandLine"], r"netsh(?:\.exe)?\"?\s+advfirewall\s+firewall\s+add\s+rule.*action=allow")},
    {"id": "R10", "name": "Service binary path changed (sc config/create binPath)", "tech": ["T1543.003"],
     "tactic": "Persistence / Privilege Escalation",
     "fn": lambda d: proc_create(d) & contains(d["CommandLine"], r"\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?(?:config|create)\b.*binpath=")},
    {"id": "R11", "name": "sc.exe run against a remote host", "tech": ["T1021.002"],
     "tactic": "Lateral Movement",
     "fn": lambda d: proc_create(d) & contains(d["CommandLine"], r"\bsc(?:\.exe)?\s+\\\\")},
    {"id": "R12", "name": "Run key value set (autostart persistence)", "tech": ["T1547.001"],
     "tactic": "Persistence",
     "fn": lambda d: d["is_sysmon"] & (d["EventID"] == 13) & contains(d["TargetObject"], r"\\currentversion\\run(?:once)?\\")},
    {"id": "R13", "name": "Local Administrators group enumeration", "tech": ["T1069.001"],
     "tactic": "Discovery",
     "fn": lambda d: proc_create(d) & contains(d["CommandLine"], r"\bnet1?(?:\.exe)?\"?\s+localgroup\s+administrators")},
    {"id": "R14", "name": "CreateRemoteThread from a non-system process", "tech": ["T1055.002"],
     "tactic": "Defense Evasion / Privilege Escalation",
     "fn": lambda d: d["is_sysmon"] & (d["EventID"] == 8) & ~basename(d["SourceImage"]).isin(SYSTEM_REMOTE_THREAD_SOURCES)},
    {"id": "R15", "name": "Python built-in web server started", "tech": ["T1059.006"],
     "tactic": "Execution",
     "fn": lambda d: proc_create(d) & contains(d["CommandLine"], r"http\.server|simplehttpserver")},
    {"id": "R16", "name": "Scheduled task created", "tech": ["T1053.005"],
     "tactic": "Persistence / Lateral Movement",
     "fn": lambda d: (proc_create(d) & contains(d["CommandLine"], r"schtasks(?:\.exe)?\"?\s.*/create"))
     | ((d["Channel"].astype(str).str.lower() == "security") & (d["EventID"] == 4698))},
    {"id": "R17", "name": "Seatbelt enumeration tool executed (name-based)", "tech": ["T1012"],
     "tactic": "Discovery",
     "fn": lambda d: proc_create(d) & (basename(d["Image"]).str.contains("seatbelt")
                                       | d["OriginalFileName"].str.lower().str.contains("seatbelt"))},
]


def parent_tech(t: str) -> str:
    return t.split(".")[0]


def main():
    OUT_DIR.mkdir(exist_ok=True)
    df = load_events()
    scen = pd.read_csv("scenarios.csv")
    scen["parent_tech"] = scen["technique"].str.split(";").str[0].map(parent_tech)

    # ---- Run the rules ----
    masks = {}
    for r in RULES:
        masks[r["id"]] = r["fn"](df).fillna(False)
    alert_cols = pd.DataFrame(masks)
    df["any_alert"] = alert_cols.any(axis=1)

    # ---- Matrix: rule x scenario (alert counts) ----
    matrix = pd.DataFrame(0, index=[r["id"] for r in RULES], columns=scen["scenario"])
    for r in RULES:
        counts = df[masks[r["id"]]].groupby("scenario").size()
        for s, c in counts.items():
            matrix.loc[r["id"], s] = c
    matrix.to_csv(OUT_DIR / "alert_matrix.csv")

    # ---- Coverage and noise ----
    rule_tech = {r["id"]: {parent_tech(t) for t in r["tech"]} for r in RULES}
    rows_cov = []
    for _, s in scen.iterrows():
        expected = [rid for rid, techs in rule_tech.items() if s["parent_tech"] in techs]
        fired_expected = [rid for rid in expected if matrix.loc[rid, s["scenario"]] > 0]
        rows_cov.append({
            "scenario": s["scenario"], "title": s["title"], "technique": s["technique"],
            "rules_for_technique": ",".join(expected) or "none written",
            "detected": bool(fired_expected),
            "rules_fired": ",".join(fired_expected),
        })
    cov = pd.DataFrame(rows_cov)
    cov.to_csv(OUT_DIR / "scenario_coverage.csv", index=False)

    # Alerts that fired in a scenario NOT labelled with that rule's technique
    off = []
    for r in RULES:
        for s in scen.itertuples():
            n = int(matrix.loc[r["id"], s.scenario])
            if n and s.parent_tech not in rule_tech[r["id"]]:
                ex = df[masks[r["id"]] & (df["scenario"] == s.scenario)].iloc[0]
                off.append({"rule": r["id"], "rule_name": r["name"], "scenario": s.scenario,
                            "labelled_technique": s.technique, "alerts": n,
                            "example_command_or_object": (ex["CommandLine"] or ex["TargetObject"]
                                                          or f"{ex['SourceImage']} -> {ex['TargetImage']}")[:160]})
    off_df = pd.DataFrame(off)
    off_df.to_csv(OUT_DIR / "off_scenario_alerts.csv", index=False)

    # Per-rule summary
    rule_rows = []
    for r in RULES:
        total = int(masks[r["id"]].sum())
        in_scen = int(sum(matrix.loc[r["id"], s.scenario] > 0 for s in scen.itertuples()
                          if s.parent_tech in rule_tech[r["id"]]))
        rule_rows.append({"rule": r["id"], "name": r["name"], "attack": ";".join(r["tech"]),
                          "tactic": r["tactic"], "total_alerts": total,
                          "scenarios_fired": int((matrix.loc[r["id"]] > 0).sum()),
                          "scenarios_matching_label": in_scen})
    pd.DataFrame(rule_rows).to_csv(OUT_DIR / "rule_summary.csv", index=False)

    # Alert-level export (one row per alerted event) for the Excel triage workbook
    alert_rows = []
    for r in RULES:
        sub = df[masks[r["id"]]]
        for _, e in sub.iterrows():
            if e["CommandLine"]:
                evidence = e["CommandLine"]
            elif e["TargetObject"]:
                evidence = f"{e['TargetObject']} = {str(e['Details'])[:120]}"
            elif e["SourceImage"] or e["TargetImage"]:
                evidence = f"{e['SourceImage']} -> {e['TargetImage']} (access {e['GrantedAccess'] or 'n/a'})"
            else:
                evidence = f"Scheduled task {e['TaskName']}"
            alert_rows.append({
                "time_utc": e["ts"].strftime("%Y-%m-%d %H:%M:%S"),
                "host": e["Hostname"] or "", "user": e["User"] if isinstance(e["User"], str) else "",
                "scenario": e["scenario"], "rule_id": r["id"],
                "event_source": ("Sysmon " if e["is_sysmon"] else str(e["Channel"]) + " ") + str(int(e["EventID"])),
                "evidence": evidence[:300],
            })
    alerts_df = pd.DataFrame(alert_rows).sort_values(["scenario", "time_utc", "rule_id"]).reset_index(drop=True)
    alerts_df.insert(0, "alert_id", [f"A{i + 1:03d}" for i in range(len(alerts_df))])
    alerts_df.to_csv(OUT_DIR / "alerts.csv", index=False)

    # Event-type profile and alert reduction
    profile = (df.groupby(["scenario"]).agg(events=("EventID", "size"),
                                            alerts=("any_alert", "sum")).reset_index())
    profile.to_csv(OUT_DIR / "events_vs_alerts.csv", index=False)

    # ---- Charts ----
    fig, ax = plt.subplots(figsize=(11, 6))
    data = (matrix > 0).astype(int).values
    ax.imshow(data, cmap="Greens", aspect="auto")
    ax.set_xticks(range(len(matrix.columns)))
    ax.set_xticklabels([c.replace("_", " ")[:28] for c in matrix.columns], rotation=70, ha="right", fontsize=7)
    ax.set_yticks(range(len(matrix.index)))
    ax.set_yticklabels([f"{r['id']} {r['name'][:38]}" for r in RULES], fontsize=7)
    ax.set_title("Which detection rule fired in which attack scenario")
    plt.tight_layout()
    plt.savefig(OUT_DIR / "coverage_heatmap.png", dpi=150)
    plt.close()

    ev = profile.sort_values("events")
    plt.figure(figsize=(9, 6))
    plt.barh(ev["scenario"].str.replace("_", " ").str[:40], ev["events"], label="All events")
    plt.barh(ev["scenario"].str.replace("_", " ").str[:40], ev["alerts"], label="Alerted events")
    plt.xscale("log")
    plt.legend()
    plt.title("Events collected vs events alerted, per scenario")
    plt.tight_layout()
    plt.savefig(OUT_DIR / "events_vs_alerts.png", dpi=150)
    plt.close()

    # ---- Summary ----
    detected = int(cov["detected"].sum())
    total_ev = len(df)
    total_al = int(df["any_alert"].sum())
    lines = [
        "# Results summary (auto-generated)\n",
        f"- Scenarios: **{len(scen)}** real attack simulations, **{scen['parent_tech'].nunique()}** distinct ATT&CK techniques",
        f"- Events analysed: **{total_ev:,}** (Sysmon: {int(df['is_sysmon'].sum()):,})",
        f"- Detection rules: **{len(RULES)}**",
        f"- Scenarios where a matching rule fired: **{detected} of {len(scen)}** ({detected / len(scen) * 100:.0f}%)",
        f"- Events raised as alerts: **{total_al:,}** ({total_al / total_ev * 100:.2f}% of all events), "
        f"a **{total_ev / max(total_al, 1):.0f}x** reduction",
        f"- Alerts firing outside their labelled scenario: **{len(off_df)}** rule/scenario pairs\n",
        "## Scenario coverage\n", cov.to_markdown(index=False),
        "\n## Rule summary\n", pd.DataFrame(rule_rows).to_markdown(index=False),
        "\n## Alerts outside the labelled scenario (review manually)\n",
        off_df.to_markdown(index=False) if len(off_df) else "None",
    ]
    (OUT_DIR / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
