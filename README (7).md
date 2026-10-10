# Windows Endpoint Threat Hunting with Sysmon (MITRE ATT&CK)

I took real Windows endpoint logs from 18 simulated attacks and wrote my own detection rules for them in Python, the way a SOC analyst or detection engineer would. Then I triaged every alert in an Excel workbook, the way an analyst works a queue, and checked what the rules caught, what they missed, and what they got wrong.

![Coverage heatmap](results/coverage_heatmap.png)

---

## Why I built this

SOC analysts spend most of their time reading endpoint logs and deciding whether something is an attack. I wanted a project that shows that skill directly: raw Sysmon events in, ATT&CK-mapped detections and an incident write-up out. I also wanted the dataset to be small enough that anyone can download and run the whole thing in a minute.

---

## Dataset

**OTRF Security-Datasets** (Open Threat Research Forge, formerly known as Mordor), a public repository of real Windows telemetry recorded while attacks were run in a lab.

- Source: https://github.com/OTRF/Security-Datasets (MIT licence)
- I used **18 host-telemetry scenarios**, about **28 MB** once unzipped and under 2 MB zipped
- **16,240 events** in total, including 9,476 Sysmon events, plus Windows Security, PowerShell and WMI logs
- Each scenario is one known ATT&CK technique, and the dataset's own metadata gives the label. They are listed in `scenarios.csv`
- Data is not committed to this repo. `download_data.py` fetches it

The scenarios cover 12 ATT&CK techniques: LSASS memory dumping (three ways), SAM and LSA secrets dumping, signed-binary proxy execution (mshta, cmstp, InstallUtil), BITS download, firewall changes, service modification, scheduled tasks, Run-key persistence, remote service control, process injection, and discovery.

---

## What I did

1. **Loaded all the events** into one pandas table and normalised the fields (process, command line, parent, target, timestamps).
2. **Wrote 17 detection rules**, Sigma-style, each mapped to an ATT&CK technique. Examples:
   - R02: LSASS opened with a dump-capable access mask by a non-system process (T1003.001)
   - R07: `InstallUtil.exe` with `/logfile=` or `/u` used to run a payload (T1218.004)
   - R14: `CreateRemoteThread` from a non-system process (T1055)
3. **Compared the alerts to the scenario labels** to see which scenarios each rule caught.
4. **Reviewed every alert that fired outside its labelled scenario**, to separate real false positives from gaps in the labels.
5. **Built an Excel triage workbook** (`results/SOC_Alert_Triage.xlsx`) with all 30 alerts. Each has a severity, a triage status and verdict (dropdowns), and my notes after reading the raw event. The summary, rule, scenario and coverage sheets are all live formulas over the alerts sheet, with charts.
6. **Wrote an incident report** for one of the attacks, with a timeline from the raw events (`incident_report.md`).

---

## How to run it

```bash
pip install -r requirements.txt
python download_data.py     # fetches the 18 scenarios into ./data
python detect.py            # runs the rules, writes ./results (including alerts.csv)
python build_workbook.py    # builds results/SOC_Alert_Triage.xlsx
```

---

## Results

| Measure | Result |
|---|---|
| Attack scenarios | 18, covering 12 distinct ATT&CK techniques |
| Events analysed | 16,240 |
| Detection rules written | 17 |
| Events raised as alerts | 30 (0.18% of all events) |
| Scenarios where a matching rule fired | 18 of 18 |
| Alerts I reviewed one by one | 30 (all confirmed as attacker behaviour in the lab simulations) |
| Alerts outside their labelled scenario | 2 alerts, one rule/scenario pair (reviewed below) |

![Events vs alerts](results/events_vs_alerts.png)

**The alerts outside their label.** Rule R09 (firewall rule added to allow inbound traffic) also fired in the `psh_python_webserver` scenario, which is labelled as Python execution. The command was `netsh advfirewall firewall add rule name=python.exe dir=in action=allow`, which really does open the firewall for the Python web server. So this is a correct detection of behaviour the label didn't mention, not a false positive.

**Some alerts came from rules that cover several scenarios.** LSASS dumping, for example, was detected three different ways (comsvcs command line, LSASS access mask, and `reg save` of registry hives), so one technique does not depend on one rule.

Full tables are in `results/` (`scenario_coverage.csv`, `rule_summary.csv`, `alert_matrix.csv`, `off_scenario_alerts.csv`).

---

## Be careful with these numbers

I want to be upfront about what "18 of 18" means. **I wrote the rules after looking at the scenarios, so catching all of them is expected and is not evidence the rules would catch real attacks.** The heatmap is nearly a diagonal for that reason. What the results do show is:

- the rules are specific, since they raise only 30 alerts out of 16,240 events;
- every alert I reviewed was real attacker behaviour, with none from normal background activity in these captures.

Other limits:

- **No benign-only baseline.** The only normal activity is whatever happened on the lab machines during each capture, so I can't estimate a real-world false-positive rate. A real network would be far noisier.
- **Several rules are easy to evade.** R17 matches the tool name `Seatbelt.exe`, so renaming the file would defeat it. The command-line rules can be dodged with different arguments or obfuscation.
- **One host type, one lab.** Windows 10 workstations and a domain controller in a lab, with Sysmon configured to log a lot.
- **Each scenario is one technique.** Real intrusions chain many steps together.

**What I'd do next:** test the rules on a different dataset I haven't looked at, add a benign baseline, convert the rules to real Sigma YAML, and try them in Splunk or Elastic.

---

## What I learned

- Command-line rules are quick to write but fragile. Behaviour-based rules, like "a non-system process opens LSASS with a full-access mask", survive renaming much better.
- Telling a false positive from a labelling gap needs actually reading the event. The firewall rule looked wrong until I read the command.
- Detecting the same technique from more than one angle (command line, process access, file creation) is worth the extra rules.

---

## Tools

Python (pandas, matplotlib, openpyxl), Excel (formulas, data validation, conditional formatting, charts), Sysmon and Windows event logs, MITRE ATT&CK, Sigma-style detection logic

## Repository structure

```
├── README.md
├── incident_report.md
├── detect.py
├── build_workbook.py
├── download_data.py
├── scenarios.csv
├── requirements.txt
└── results/
    ├── SOC_Alert_Triage.xlsx
    ├── alerts.csv
    └── (tables and charts)
```

## Credits

Dataset: Open Threat Research Forge, *Security-Datasets* (MIT licence). Dataset metadata and scenario labels come from the project. Detection rules, analysis and incident report are my own.

---

## Resume version

**Windows Endpoint Threat Hunting with Sysmon (MITRE ATT&CK)** | Python, pandas, Sysmon, Sigma-style rules | [GitHub link]

- Analysed 16,240 real Windows endpoint events (Sysmon, Security, PowerShell) from 18 simulated attacks across 12 MITRE ATT&CK techniques, including LSASS credential dumping, signed-binary proxy execution and process injection.
- Wrote 17 ATT&CK-mapped, Sigma-style detection rules in Python that reduced the data to 30 alerts (0.18% of events), and reviewed each alert's raw event to confirm it was real attacker behaviour.
- Built an Excel triage workbook with 688 live formulas (summary KPIs, ATT&CK tactic and rule breakdowns, rule-by-scenario coverage matrix), dropdown-driven verdicts, conditional formatting and charts.
- Documented limitations, including that rules were written with sight of the data and name-based rules are easy to evade, and proposed validating on unseen data and a benign baseline.
- Wrote an incident report for an LSASS credential-dumping attack with a millisecond timeline, ATT&CK mapping, severity assessment and containment steps.

**Shorter version (2 bullets):**

- Built 17 ATT&CK-mapped detection rules in Python over 16,240 real Windows Sysmon/Security events from 18 attack simulations, reducing them to 30 alerts, each triaged in an Excel workbook (formula-driven dashboard, ATT&CK coverage matrix, charts).
- Wrote an incident report for LSASS credential dumping (timeline, ATT&CK mapping, severity, containment) and documented the rules' limitations and evasion risks.

**About me:** Samson Savio | Data Analyst moving into SOC and security analytics | Bengaluru, India | [LinkedIn](https://linkedin.com/in/samson-savio-263202165)
