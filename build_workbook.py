"""
Build the Excel SOC alert-triage workbook from the detection results.

Run detect.py first (it writes results/alerts.csv), then:
    python build_workbook.py
Output: results/SOC_Alert_Triage.xlsx

Design: every number on the Summary, Rules, Scenarios and Coverage sheets is an
Excel formula that reads the Alerts sheet, so if you change a verdict, add an
alert row or edit a severity, everything recalculates.
Blue text = input cells you can edit. Black text = formulas.
"""
from datetime import datetime
from pathlib import Path

import pandas as pd
from openpyxl import Workbook
from openpyxl.chart import BarChart, Reference
from openpyxl.formatting.rule import ColorScaleRule, CellIsRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

import detect  # reuse the rule definitions so names/techniques stay in sync

OUT = Path("results/SOC_Alert_Triage.xlsx")
MAXROW = 500  # formulas read Alerts rows 2..500 so new alerts can be appended

FONT = "Arial"
HDR_FILL = PatternFill("solid", start_color="1F3864")
SUB_FILL = PatternFill("solid", start_color="D9E2F3")
INPUT_FILL = PatternFill("solid", start_color="FFF2CC")
thin = Side(style="thin", color="BFBFBF")
BORDER = Border(left=thin, right=thin, top=thin, bottom=thin)

# ---- Analyst judgement (documented on the Summary sheet) ----
SEVERITY = {"R01": "High", "R02": "High", "R03": "High", "R04": "High", "R14": "High",
            "R05": "Medium", "R06": "Medium", "R07": "Medium", "R08": "Medium", "R09": "Medium",
            "R10": "Medium", "R11": "Medium", "R12": "Medium", "R16": "Medium",
            "R13": "Low", "R15": "Low", "R17": "Low"}
PRIMARY_TACTIC = {"R01": "Credential Access", "R02": "Credential Access", "R03": "Credential Access",
                  "R04": "Credential Access", "R05": "Defense Evasion", "R06": "Defense Evasion",
                  "R07": "Defense Evasion", "R08": "Defense Evasion", "R09": "Defense Evasion",
                  "R10": "Persistence", "R11": "Lateral Movement", "R12": "Persistence",
                  "R13": "Discovery", "R14": "Defense Evasion", "R15": "Execution",
                  "R16": "Persistence", "R17": "Discovery"}
LOGIC = {
    "R01": "Process create: command line has comsvcs and MiniDump",
    "R02": "Sysmon 10: lsass.exe opened with a dump-capable access mask by a non-system process",
    "R03": "Process create: reg save of HKLM SAM, SECURITY or SYSTEM hive",
    "R04": "Process create: esentutl with /vss (copy from Volume Shadow Copy)",
    "R05": "Process create: mshta with vbscript:, javascript:, a URL or .hta",
    "R06": "Process create: cmstp with /s or /au (silent INF install)",
    "R07": "Process create: InstallUtil with /u or /logfile=",
    "R08": "Process create: bitsadmin with /transfer or /addfile",
    "R09": "Process create: netsh advfirewall firewall add rule ... action=allow",
    "R10": "Process create: sc config/create with binPath=",
    "R11": "Process create: sc.exe aimed at a remote host (\\\\host)",
    "R12": "Sysmon 13: value written under CurrentVersion\\Run or RunOnce",
    "R13": "Process create: net/net1 localgroup administrators",
    "R14": "Sysmon 8: CreateRemoteThread from a non-system source process",
    "R15": "Process create: python http.server / SimpleHTTPServer",
    "R16": "Process create: schtasks /create, or Security event 4698",
    "R17": "Process create: image or original filename is Seatbelt (name-based, easy to evade)",
}
# Short analyst note per alert, written after reading each event
NOTES = {
    "A001": "BITS transfer pulling a script from a public GitHub URL to a Temp .ps1; classic download-and-run staging.",
    "A002": "Dumpert (Outflank) opens LSASS with full access (0x1fffff); direct-syscall dumping tool.",
    "A003": "Second full-access open of LSASS by the same tool, same run.",
    "A004": "mshta runs VBScript that launches PowerShell; signed-binary proxy execution.",
    "A005": "Inbound allow rule opened on TCP 450 via netsh; weakens host firewall.",
    "A006": "PsExec launches 'reg save' of the SECURITY secrets key as SYSTEM (-s) to a Temp file.",
    "A007": "Same reg save now running under NT AUTHORITY\\SYSTEM, spawned by the PsExec service.",
    "A008": "esentutl copies the SAM hive out of a shadow copy to C:\\ProgramData\\SAM; bypasses the file lock.",
    "A009": "Seatbelt run with -group=user to enumerate users and groups; name-based match only.",
    "A010": "Service 'Fax' binPath changed to run PowerShell; service hijack for persistence/privilege escalation.",
    "A011": "Fax binPath restored to fxssvc.exe; this is test cleanup, but still the same technique.",
    "A012": "cmd wrapper launching InstallUtil against GruntHTTP.dll; parent is the Covenant implant GruntHTTP.exe.",
    "A013": "InstallUtil itself executing the Covenant payload DLL (/u triggers the uninstall routine).",
    "A014": "cmd wrapper running sc.exe against domain controller MORDORDC; remote service query.",
    "A015": "sc.exe querying service IKEEXT on the domain controller over SMB/svcctl.",
    "A016": "PowerShell command written to HKLM Run key 'Updater'; autostart persistence.",
    "A017": "net.exe localgroup Administrators; local admin discovery, spawned from PowerShell.",
    "A018": "net1.exe child of net.exe, same command (expected duplicate).",
    "A019": "reg.exe saves the SAM hive to a local file; offline credential extraction.",
    "A020": "cmstp /s with an .inf and /au; UAC bypass through signed binary.",
    "A021": "rundll32 calls comsvcs.dll MiniDump on PID 756 (lsass) writing lsass-comsvcs.dmp. See incident_report.md.",
    "A022": "rundll32 opens lsass.exe with full access (0x1fffff), 31 ms after the dump process starts.",
    "A023": "rundll32 opens lsass.exe with 0x1410 (query + read memory), same dump run.",
    "A024": "netsh adds inbound allow rule for python.exe (TCP). Real behaviour the scenario label does not mention.",
    "A025": "Same rule for UDP; second half of the firewall change.",
    "A026": "Python http.server on port 8000; ad-hoc web server for file staging or exfiltration.",
    "A027": "PurpleSharp.exe injects a thread into notepad.exe via CreateRemoteThread; process injection.",
    "A028": "Security 4698: scheduled task created; corroborates the schtasks command below.",
    "A029": "cmd wrapper creating a task that runs at startup as SYSTEM on WORKSTATION6 (/S); remote scheduled task.",
    "A030": "schtasks.exe /create itself, same task; ONSTART as SYSTEM on a remote host.",
}


def style_header(ws, row, ncols, fill=HDR_FILL):
    for c in range(1, ncols + 1):
        cell = ws.cell(row=row, column=c)
        cell.font = Font(name=FONT, bold=True, color="FFFFFF" if fill is HDR_FILL else "000000", size=10)
        cell.fill = fill
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = BORDER


def base_font(ws, rows, cols, bold=False, color="000000", size=10):
    for r in rows:
        for c in cols:
            cell = ws.cell(row=r, column=c)
            cell.font = Font(name=FONT, size=size, bold=bold, color=color)


def main():
    alerts = pd.read_csv("results/alerts.csv", keep_default_na=False)
    scen = pd.read_csv("scenarios.csv")
    ev = pd.read_csv("results/events_vs_alerts.csv").set_index("scenario")["events"]
    n_alerts, n_scen, n_rules = len(alerts), len(scen), len(detect.RULES)

    wb = Workbook()
    ws_sum = wb.active
    ws_sum.title = "Summary"
    ws_al = wb.create_sheet("Alerts")
    ws_ru = wb.create_sheet("Rules")
    ws_sc = wb.create_sheet("Scenarios")
    ws_cv = wb.create_sheet("Coverage")

    A = lambda col: f"Alerts!${col}$2:${col}${MAXROW}"  # noqa: E731

    # ------------------------------------------------------------------ Rules
    rule_hdr = ["Rule ID", "Rule name", "ATT&CK technique(s)", "Primary tactic", "Severity",
                "Detection logic", "Alerts", "Scenarios fired", "Share of alerts"]
    ws_ru.append(rule_hdr)
    style_header(ws_ru, 1, len(rule_hdr))
    for i, r in enumerate(detect.RULES, start=2):
        ws_ru.append([r["id"], r["name"], ";".join(r["tech"]), PRIMARY_TACTIC[r["id"]],
                      SEVERITY[r["id"]], LOGIC[r["id"]],
                      f"=COUNTIF({A('F')},A{i})",
                      f"=COUNTIF(Coverage!B{i}:{get_column_letter(1 + n_scen)}{i},\">0\")",
                      f"=IF(SUM($G$2:$G${n_rules + 1})=0,0,G{i}/SUM($G$2:$G${n_rules + 1}))"])
    last_rule = n_rules + 1
    base_font(ws_ru, range(2, last_rule + 1), range(1, 10))
    for rr in range(2, last_rule + 1):
        ws_ru.cell(rr, 5).font = Font(name=FONT, size=10, color="0000FF")  # editable input
        ws_ru.cell(rr, 5).fill = INPUT_FILL
        ws_ru.cell(rr, 9).number_format = "0.0%"
        for c in range(1, 10):
            ws_ru.cell(rr, c).border = BORDER
            ws_ru.cell(rr, c).alignment = Alignment(vertical="top", wrap_text=(c in (2, 6)))
    for col, w in zip("ABCDEFGHI", [8, 44, 20, 20, 10, 70, 9, 10, 10]):
        ws_ru.column_dimensions[col].width = w
    ws_ru.freeze_panes = "A2"
    dv_sev = DataValidation(type="list", formula1='"High,Medium,Low"', allow_blank=False)
    ws_ru.add_data_validation(dv_sev)
    dv_sev.add(f"E2:E{last_rule}")
    ws_ru.cell(last_rule + 2, 1, "Severity is my own judgement (credential theft and injection = High; "
               "persistence and evasion = Medium; discovery and staging = Low). Edit the yellow cells to change it.")
    ws_ru.cell(last_rule + 2, 1).font = Font(name=FONT, size=9, italic=True)

    # -------------------------------------------------------------- Scenarios
    sc_hdr = ["Scenario", "Title", "ATT&CK technique", "Tactics (dataset label)", "Events",
              "Alerts", "Alerts matching label", "Detected?", "Alert rate", "Parent technique"]
    ws_sc.append(sc_hdr)
    style_header(ws_sc, 1, len(sc_hdr))
    for i, s in enumerate(scen.itertuples(), start=2):
        ws_sc.append([s.scenario, s.title, s.technique, s.tactics, int(ev[s.scenario]),
                      f"=COUNTIF({A('E')},A{i})",
                      f"=COUNTIFS({A('E')},A{i},{A('N')},\"Yes\")",
                      f"=IF(G{i}>0,\"Yes\",\"No\")",
                      f"=IF(E{i}=0,0,F{i}/E{i})",
                      f"=LEFT(C{i},5)"])
    last_sc = n_scen + 1
    tot = last_sc + 1
    ws_sc.cell(tot, 1, "Total")
    ws_sc.cell(tot, 5, f"=SUM(E2:E{last_sc})")
    ws_sc.cell(tot, 6, f"=SUM(F2:F{last_sc})")
    ws_sc.cell(tot, 7, f"=SUM(G2:G{last_sc})")
    ws_sc.cell(tot, 8, f"=COUNTIF(H2:H{last_sc},\"Yes\")&\" of \"&COUNTA(A2:A{last_sc})")
    ws_sc.cell(tot, 9, f"=IF(E{tot}=0,0,F{tot}/E{tot})")
    base_font(ws_sc, range(2, tot + 1), range(1, 11))
    for rr in range(2, last_sc + 1):
        ws_sc.cell(rr, 5).font = Font(name=FONT, size=10, color="0000FF")  # hardcoded from detect.py
    base_font(ws_sc, [tot], range(1, 11), bold=True)
    for rr in range(2, tot + 1):
        ws_sc.cell(rr, 5).number_format = "#,##0"
        ws_sc.cell(rr, 9).number_format = "0.00%"
        for c in range(1, 11):
            ws_sc.cell(rr, c).border = BORDER
    for c in range(1, 11):
        ws_sc.cell(tot, c).fill = SUB_FILL
    for col, w in zip("ABCDEFGHIJ", [58, 40, 16, 20, 9, 8, 12, 10, 10, 12]):
        ws_sc.column_dimensions[col].width = w
    ws_sc.freeze_panes = "B2"
    ws_sc.cell(tot + 2, 1, "Events column: hardcoded from detect.py output (results/events_vs_alerts.csv). "
               "Labels (technique, tactics): OTRF Security-Datasets metadata, see scenarios.csv.")
    ws_sc.cell(tot + 2, 1).font = Font(name=FONT, size=9, italic=True)
    ws_sc.conditional_formatting.add(f"H2:H{last_sc}", CellIsRule(operator="equal", formula=['"Yes"'],
                                     fill=PatternFill("solid", start_color="C6EFCE")))
    ws_sc.conditional_formatting.add(f"H2:H{last_sc}", CellIsRule(operator="equal", formula=['"No"'],
                                     fill=PatternFill("solid", start_color="FFC7CE")))

    # ----------------------------------------------------------------- Alerts
    al_hdr = ["Alert ID", "Time (UTC)", "Host", "User", "Scenario", "Rule ID", "Rule name",
              "ATT&CK technique(s)", "Tactic", "Severity", "Event source", "Evidence",
              "Scenario technique", "Matches label?", "Triage status", "Verdict", "Analyst notes"]
    ws_al.append(al_hdr)
    style_header(ws_al, 1, len(al_hdr))
    for i, a in enumerate(alerts.itertuples(), start=2):
        ws_al.append([
            a.alert_id, datetime.strptime(a.time_utc, "%Y-%m-%d %H:%M:%S"), a.host, a.user or "n/a",
            a.scenario, a.rule_id,
            f"=INDEX(Rules!$B$2:$B${last_rule},MATCH($F{i},Rules!$A$2:$A${last_rule},0))",
            f"=INDEX(Rules!$C$2:$C${last_rule},MATCH($F{i},Rules!$A$2:$A${last_rule},0))",
            f"=INDEX(Rules!$D$2:$D${last_rule},MATCH($F{i},Rules!$A$2:$A${last_rule},0))",
            f"=INDEX(Rules!$E$2:$E${last_rule},MATCH($F{i},Rules!$A$2:$A${last_rule},0))",
            a.event_source, a.evidence,
            f"=INDEX(Scenarios!$C$2:$C${last_sc},MATCH($E{i},Scenarios!$A$2:$A${last_sc},0))",
            f"=IF(ISNUMBER(SEARCH(LEFT(M{i},5),H{i})),\"Yes\",\"No\")",
            "Closed", "True positive", NOTES.get(a.alert_id, ""),
        ])
    last_al = n_alerts + 1
    base_font(ws_al, range(2, last_al + 1), range(1, 18))
    for rr in range(2, last_al + 1):
        ws_al.cell(rr, 2).number_format = "yyyy-mm-dd hh:mm:ss"
        for c in (15, 16, 17):  # analyst inputs
            ws_al.cell(rr, c).font = Font(name=FONT, size=10, color="0000FF")
            ws_al.cell(rr, c).fill = INPUT_FILL
        for c in range(1, 18):
            ws_al.cell(rr, c).border = BORDER
            ws_al.cell(rr, c).alignment = Alignment(vertical="top", wrap_text=(c in (7, 12, 17)))
    for col, w in zip("ABCDEFGHIJKLMNOPQ",
                      [9, 19, 18, 22, 34, 8, 36, 18, 16, 9, 13, 60, 12, 10, 12, 14, 60]):
        ws_al.column_dimensions[col].width = w
    ws_al.freeze_panes = "C2"
    ws_al.auto_filter.ref = f"A1:Q{last_al}"
    dv_status = DataValidation(type="list", formula1='"New,Investigating,Closed"', allow_blank=True)
    dv_verdict = DataValidation(type="list",
                                formula1='"True positive,False positive,Benign / expected,Needs review"',
                                allow_blank=True)
    ws_al.add_data_validation(dv_status)
    ws_al.add_data_validation(dv_verdict)
    dv_status.add(f"O2:O{MAXROW}")
    dv_verdict.add(f"P2:P{MAXROW}")
    red = PatternFill("solid", start_color="F8CBAD")
    amber = PatternFill("solid", start_color="FFE699")
    green = PatternFill("solid", start_color="E2EFDA")
    ws_al.conditional_formatting.add(f"J2:J{MAXROW}", CellIsRule(operator="equal", formula=['"High"'], fill=red))
    ws_al.conditional_formatting.add(f"J2:J{MAXROW}", CellIsRule(operator="equal", formula=['"Medium"'], fill=amber))
    ws_al.conditional_formatting.add(f"J2:J{MAXROW}", CellIsRule(operator="equal", formula=['"Low"'], fill=green))
    ws_al.conditional_formatting.add(f"N2:N{MAXROW}", CellIsRule(operator="equal", formula=['"No"'], fill=amber))

    # --------------------------------------------------------------- Coverage
    ws_cv.cell(1, 1, "Rule \\ Scenario")
    for j, s in enumerate(scen["scenario"], start=2):
        ws_cv.cell(1, j, s)
    ws_cv.cell(1, 2 + n_scen, "Total")
    style_header(ws_cv, 1, 2 + n_scen)
    for j in range(2, 2 + n_scen):
        ws_cv.cell(1, j).alignment = Alignment(textRotation=90, horizontal="center", vertical="bottom")
    ws_cv.row_dimensions[1].height = 230
    for i, r in enumerate(detect.RULES, start=2):
        ws_cv.cell(i, 1, f"{r['id']} {r['name']}")
        for j in range(2, 2 + n_scen):
            col = get_column_letter(j)
            ws_cv.cell(i, j, f"=COUNTIFS({A('F')},{r['id']!r},{A('E')},{col}$1)".replace("'", '"'))
        ws_cv.cell(i, 2 + n_scen, f"=SUM(B{i}:{get_column_letter(1 + n_scen)}{i})")
    tr = n_rules + 2
    ws_cv.cell(tr, 1, "Total")
    for j in range(2, 3 + n_scen):
        col = get_column_letter(j)
        ws_cv.cell(tr, j, f"=SUM({col}2:{col}{tr - 1})")
    base_font(ws_cv, range(2, tr + 1), range(1, 3 + n_scen))
    base_font(ws_cv, [tr], range(1, 3 + n_scen), bold=True)
    for rr in range(2, tr + 1):
        for c in range(1, 3 + n_scen):
            ws_cv.cell(rr, c).border = BORDER
            if c > 1:
                ws_cv.cell(rr, c).alignment = Alignment(horizontal="center")
    ws_cv.column_dimensions["A"].width = 52
    for j in range(2, 3 + n_scen):
        ws_cv.column_dimensions[get_column_letter(j)].width = 5.5
    ws_cv.conditional_formatting.add(
        f"B2:{get_column_letter(1 + n_scen)}{tr - 1}",
        ColorScaleRule(start_type="num", start_value=0, start_color="FFFFFF",
                       end_type="max", end_color="63BE7B"))
    ws_cv.freeze_panes = "B2"
    ws_cv.cell(tr + 2, 1, "Cells count alerts for that rule in that scenario (formulas over the Alerts sheet). "
               "The near-diagonal pattern is expected because I wrote the rules after seeing the scenarios.")
    ws_cv.cell(tr + 2, 1).font = Font(name=FONT, size=9, italic=True)

    # ---------------------------------------------------------------- Summary
    ws = ws_sum
    ws["A1"] = "SOC Alert Triage Workbook: Windows Endpoint Threat Hunting"
    ws["A1"].font = Font(name=FONT, size=16, bold=True, color="1F3864")
    ws["A2"] = ("Real Sysmon/Security telemetry from 18 simulated attacks (OTRF Security-Datasets, MIT licence). "
                "Detections come from detect.py; this workbook is the analyst triage view.")
    ws["A2"].font = Font(name=FONT, size=10, italic=True)

    kpis = [
        ("Attack scenarios analysed", f"=COUNTA(Scenarios!A2:A{last_sc})", "0"),
        ("Distinct ATT&CK techniques", f"=SUMPRODUCT(1/COUNTIF(Scenarios!J2:J{last_sc},Scenarios!J2:J{last_sc}))", "0"),
        ("Events analysed", f"=SUM(Scenarios!E2:E{last_sc})", "#,##0"),
        ("Detection rules", f"=COUNTA(Rules!A2:A{last_rule})", "0"),
        ("Alerts raised", f"=COUNTA({A('A')})", "0"),
        ("Alert rate (alerts / events)", "=IF(B7=0,0,B9/B7)", "0.00%"),
        ("Scenarios with a matching rule firing", f"=COUNTIF(Scenarios!H2:H{last_sc},\"Yes\")", "0"),
        ("Alerts outside their labelled scenario", f"=COUNTIF({A('N')},\"No\")", "0"),
        ("Verdict: true positive", f"=COUNTIF({A('P')},\"True positive\")", "0"),
        ("Verdict: false positive", f"=COUNTIF({A('P')},\"False positive\")", "0"),
        ("Alerts without a verdict yet", "=B9-COUNTA(Alerts!$P$2:$P$500)", "0"),
    ]
    ws["A4"], ws["B4"] = "Key figures", "Value"
    style_header(ws, 4, 2)
    for k, (label, formula, fmt) in enumerate(kpis, start=5):
        ws.cell(k, 1, label)
        ws.cell(k, 2, formula)
        ws.cell(k, 2).number_format = fmt
        for c in (1, 2):
            ws.cell(k, c).font = Font(name=FONT, size=10, bold=(c == 2))
            ws.cell(k, c).border = BORDER

    # Alerts by severity
    r0 = 18
    ws.cell(r0, 1, "Alerts by severity")
    ws.cell(r0, 2, "Alerts")
    style_header(ws, r0, 2)
    for k, sev in enumerate(["High", "Medium", "Low"], start=r0 + 1):
        ws.cell(k, 1, sev)
        ws.cell(k, 2, f"=COUNTIF({A('J')},A{k})")
        for c in (1, 2):
            ws.cell(k, c).font = Font(name=FONT, size=10)
            ws.cell(k, c).border = BORDER

    # Alerts by tactic
    t0 = 24
    tactics = ["Credential Access", "Defense Evasion", "Persistence", "Lateral Movement",
               "Discovery", "Execution"]
    ws.cell(t0, 1, "Alerts by tactic (primary tactic per rule)")
    ws.cell(t0, 2, "Alerts")
    style_header(ws, t0, 2)
    for k, t in enumerate(tactics, start=t0 + 1):
        ws.cell(k, 1, t)
        ws.cell(k, 2, f"=COUNTIF({A('I')},A{k})")
        for c in (1, 2):
            ws.cell(k, c).font = Font(name=FONT, size=10)
            ws.cell(k, c).border = BORDER
    tl = t0 + len(tactics)

    ch1 = BarChart()
    ch1.type = "bar"
    ch1.title = "Alerts by tactic"
    ch1.add_data(Reference(ws, min_col=2, min_row=t0, max_row=tl), titles_from_data=True)
    ch1.set_categories(Reference(ws, min_col=1, min_row=t0 + 1, max_row=tl))
    ch1.legend = None
    ch1.height, ch1.width = 7.5, 14
    ws.add_chart(ch1, "D4")

    ch2 = BarChart()
    ch2.type = "col"
    ch2.title = "Alerts by rule"
    ch2.add_data(Reference(ws_ru, min_col=7, min_row=1, max_row=last_rule), titles_from_data=True)
    ch2.set_categories(Reference(ws_ru, min_col=1, min_row=2, max_row=last_rule))
    ch2.legend = None
    ch2.height, ch2.width = 7.5, 14
    ws.add_chart(ch2, "D20")

    # Notes / assumptions
    n0 = tl + 3
    notes = [
        "How to read this workbook",
        "Blue text on yellow = cells you can edit (severity on Rules, status / verdict / notes on Alerts).",
        "Black text = formulas. Everything on Summary, Rules, Scenarios and Coverage recalculates from the Alerts sheet.",
        "To add an alert, append a row on Alerts (up to row 500) with Alert ID, time, host, scenario and a Rule ID; the lookups fill the rest.",
        "",
        "Assumptions and sources",
        "Dataset: OTRF Security-Datasets (github.com/OTRF/Security-Datasets), MIT licence. Technique labels come from its metadata.",
        "Events per scenario: hardcoded from detect.py output (results/events_vs_alerts.csv).",
        "Severity and primary tactic per rule: my own judgement, not part of the dataset.",
        "Verdicts and notes: my review of each alert's raw event; please re-check them yourself before presenting.",
        "100% scenario coverage is expected: the rules were written after viewing the scenarios, so it does not show how they would perform on unseen data.",
    ]
    for k, text in enumerate(notes, start=n0):
        ws.cell(k, 1, text)
        ws.cell(k, 1).font = Font(name=FONT, size=10, bold=text in ("How to read this workbook", "Assumptions and sources"))
    ws.column_dimensions["A"].width = 46
    ws.column_dimensions["B"].width = 12
    ws.column_dimensions["C"].width = 3

    for sheet in wb.worksheets:
        sheet.sheet_view.showGridLines = False if sheet.title == "Summary" else True

    OUT.parent.mkdir(exist_ok=True)
    wb.save(OUT)
    print(f"saved {OUT}")


if __name__ == "__main__":
    main()
