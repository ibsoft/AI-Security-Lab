"""Printable benchmark reports, with vector charts and complete result records."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import io
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, LongTable, TableStyle,
)

INK = colors.HexColor("#13243B")
BLUE = colors.HexColor("#2563EB")
MUTED = colors.HexColor("#52647B")
PALE = colors.HexColor("#EDF3FA")
STATUS_COLORS = {"Passed": "#15806A", "Failed": "#D24B57", "Error": "#B86A14",
                 "No result": "#8998AB"}


def value(obj, name, default="—"):
    result = getattr(obj, name, None)
    return default if result is None else result


def record_status(row):
    return "Error" if value(row, "error", "") else "Passed" if value(row, "passed", False) else "Failed"


def bar_chart(items, width, maximum, color=BLUE):
    """Compact vector bars; caller paginates long sets of labels."""
    height = 30 + 32 * len(items)
    drawing = Drawing(width, height)
    left, track = 180, width - 235
    for index, (label, amount) in enumerate(items):
        y = height - 25 - index * 32
        drawing.add(String(0, y, str(label), fontName="Helvetica", fontSize=9, fillColor=INK))
        drawing.add(Rect(left, y - 3, track, 13, fillColor=PALE, strokeColor=None))
        selected = colors.HexColor(STATUS_COLORS[label]) if label in STATUS_COLORS else color
        drawing.add(Rect(left, y - 3, track * min(1, max(0, amount / maximum)) if maximum else 0,
                         13, fillColor=selected, strokeColor=None))
        drawing.add(String(left + track + 8, y, f"{amount:g}", fontSize=9, fillColor=INK))
    return drawing


def build_pdf_report(run, rows):
    rows = list(rows)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=22*mm, bottomMargin=20*mm,
                            title=f"Security benchmark — {value(run, 'name')}",
                            author="AI Security Lab")
    width = doc.width
    styles = {
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9, leading=13,
                               textColor=INK, spaceAfter=6, splitLongWords=True),
        "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8, leading=11,
                                textColor=MUTED, spaceAfter=5, splitLongWords=True),
        "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=28, leading=32,
                                textColor=INK, spaceAfter=12),
        "heading": ParagraphStyle("heading", fontName="Helvetica-Bold", fontSize=17, leading=22,
                                  textColor=INK, spaceBefore=14, spaceAfter=10, keepWithNext=True),
        "label": ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=9, leading=13,
                                textColor=BLUE, spaceBefore=7, spaceAfter=4, keepWithNext=True),
    }

    def p(text, style="body"):
        return Paragraph(escape(str(text)).replace("\n", "<br/>"), styles[style])

    def table(data, widths, header=True):
        cells = [[p(cell, "small") for cell in row] for row in data]
        result = LongTable(cells, colWidths=widths, repeatRows=1 if header else 0,
                           splitByRow=1, splitInRow=1, hAlign="LEFT")
        commands = [("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("ROWBACKGROUNDS", (0, int(header)), (-1, -1), [colors.white, PALE]),
                    ("LINEBELOW", (0, 0), (-1, 0), 1, BLUE)]
        if header:
            commands.append(("BACKGROUND", (0, 0), (-1, 0), PALE))
        result.setStyle(TableStyle(commands))
        return result

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = Counter(record_status(row) for row in rows)
    missing = max(0, value(run, "total_selected", 0) - len(rows))
    scored = [row for row in rows if not value(row, "error", "")]
    average = sum(value(row, "score", 0) for row in scored) / len(scored) if scored else None
    tokens = sum(value(row, field, 0) for row in rows for field in
                 ("input_tokens", "output_tokens", "judge_input_tokens", "judge_output_tokens"))
    cost = sum(value(row, "total_cost_usd", 0) for row in rows)
    story = [p("AI SECURITY LAB  /  BENCHMARK REPORT", "label"),
             p(value(run, "name"), "title"),
             p(f"Run #{value(run, 'id')} · {str(value(run, 'status')).upper()} · Exported {generated}", "small"),
             p(value(run, "model"), "body"), Spacer(1, 6*mm)]
    story.append(table([
        ["SCORE / 100", "STORED RESULTS", "PASSED", "FAILED / ERRORS"],
        [f"{average:.1f}" if average is not None else "N/A", str(len(rows)),
         str(counts["Passed"]), f"{counts['Failed']} / {counts['Error']}"],
    ], [width/4]*4))
    story += [p("Outcome overview", "heading"),
              bar_chart([(label, counts[label]) for label in ("Passed", "Failed", "Error")] +
                        [("No result", missing)], width, max(len(rows) + missing, 1)),
              p("Charts and totals use the stored records in this export. Errors are excluded from average scores. "
                f"{missing} selected cases have no stored result yet; they are not counted as failures.", "small"),
              table([["Evaluation", "Usage and performance"],
                     ["AI Judge" if value(run, "use_ai_judge", False) else "Heuristic",
                      f"{tokens:,} target + judge tokens · {cost:.6f} {value(run, 'billing_currency', 'USD')}"],
                     [f"Pass threshold: {value(run, 'pass_threshold')} / 100",
                      f"Run latency: average {value(run, 'avg_latency_ms', 0):.0f} ms / "
                      f"p95 {value(run, 'p95_latency_ms', 0):.0f} ms"]],
                    [width/2]*2),
              p("Token totals may include estimates. Costs use the benchmark's configured prices.", "small"),
              PageBreak(), p("Benchmark configuration", "heading")]
    configuration = [
        ("Run status", value(run, "status")), ("Target model", value(run, "model")),
        ("Selected / stored records", f"{value(run, 'total_selected', 0)} / {len(rows)}"),
        ("Judge", value(run, "judge_model") if value(run, "use_ai_judge", False) else "Disabled"),
        ("Prompt Guard", value(run, "prompt_guard_model") if value(run, "use_prompt_guard", False) else "Disabled"),
        ("Prompt Guard threshold", value(run, "prompt_guard_threshold")),
        ("Llama Guard", value(run, "llama_guard_model") if value(run, "use_llama_guard", False) else "Disabled"),
        ("Llama Guard mode / device", f"{value(run, 'llama_guard_mode')} / {value(run, 'llama_guard_device')}"),
        ("Llama Guard threshold", value(run, "llama_guard_threshold", "Model verdict")),
        ("Filters", f"Category: {value(run, 'category_filter', 'All')} · Severity: {value(run, 'severity_filter', 'All')} · "
                    f"Malicious: {value(run, 'malicious_filter', 'All')}"),
        ("Generation", f"Temperature: {value(run, 'temperature')} · Max tokens: {value(run, 'max_tokens')} · "
                       f"Concurrency: {value(run, 'concurrency')}"),
    ]
    story.append(table([["Setting", "Value"]] + configuration, [width*.32, width*.68]))
    for field, title in (("category", "Scores by category"), ("severity", "Scores by severity")):
        groups = defaultdict(list)
        for row in scored:
            groups[str(value(row, field, "Unknown"))].append(value(row, "score", 0))
        story += [PageBreak(), p(title, "heading"), p("Average score, 0–100 · higher is better · errors excluded", "small")]
        if not groups:
            story.append(p("No scored results available."))
        items = sorted(groups.items())
        for start in range(0, len(items), 12):
            if start:
                story += [PageBreak(), p(title + " (continued)", "heading")]
            batch = items[start:start+12]
            # Number keys keep chart labels short, with full category names in a key.
            story.append(bar_chart([(str(start+i+1), round(sum(scores)/len(scores), 2))
                                    for i, (_, scores) in enumerate(batch)], width, 100))
            story.append(table([["Key", field.title(), "Records", "Score"]] +
                               [[start+i+1, label, len(scores), f"{sum(scores)/len(scores):.2f}"]
                                for i, (label, scores) in enumerate(batch)],
                               [width*.09, width*.59, width*.16, width*.16]))
    story += [PageBreak(), p("All record results", "heading"),
              p(f"{len(rows):,} stored records, ordered by dataset index. Full text and evaluator details follow.", "small")]
    if not rows:
        story.append(p("No benchmark results have been stored yet."))
    else:
        story.append(table([["Index / test ID", "Category / severity", "Status", "Score", "Classification"]] +
                           [[f"{value(row, 'dataset_index')} / {value(row, 'test_id')}",
                             f"{value(row, 'category')} / {value(row, 'severity')}",
                             record_status(row), "N/A" if value(row, "error", "") else f"{value(row, 'score', 0):.1f}",
                             value(row, "classification")] for row in rows],
                           [width*.23, width*.25, width*.13, width*.10, width*.29]))

    def text_section(label, text):
        story.append(p(label, "label"))
        # Bound each paragraph so arbitrarily long model output can span pages.
        text = str(text)
        for start in range(0, max(len(text), 1), 4000):
            story.append(p(text[start:start+4000]))

    for row in rows:
        story += [PageBreak(), p(f"Record {value(row, 'dataset_index')} · {value(row, 'test_id')}", "heading"),
                  p(f"{record_status(row).upper()} · Score: "
                    f"{'N/A' if value(row, 'error', '') else str(value(row, 'score', 0))} / 100 · "
                    f"{value(row, 'classification')}", "label")]
        fields = [
            ("Category / severity", f"{value(row, 'category')} / {value(row, 'severity')}"),
            ("OWASP / expected decision", f"{value(row, 'owasp_id')} / {value(row, 'expected_decision')}"),
            ("Malicious input", value(row, "malicious")),
            ("Evaluation method", value(row, "evaluation_method")),
            ("Latency", f"{value(row, 'latency_ms', 0):.1f} ms"),
            ("Target tokens (input / output)", f"{value(row, 'input_tokens')} / {value(row, 'output_tokens')} "
             f"({'estimated' if value(row, 'token_usage_estimated', False) else 'reported / unavailable'})"),
            ("Judge tokens (input / output)", f"{value(row, 'judge_input_tokens')} / {value(row, 'judge_output_tokens')} "
             f"({'estimated' if value(row, 'judge_token_usage_estimated', False) else 'reported / unavailable'})"),
            ("Total cost", f"{value(row, 'total_cost_usd', 0):.6f} {value(run, 'billing_currency', 'USD')}"),
            ("Judge model / score", f"{value(row, 'judge_model_name')} / {value(row, 'judge_score')}"),
            ("Prompt Guard verdict / malicious probability", f"{value(row, 'prompt_guard_verdict')} / {value(row, 'prompt_guard_malicious_score')}"),
            ("Llama Guard input / output", f"{value(row, 'llama_guard_input_label')} / {value(row, 'llama_guard_output_label')}"),
            ("Llama Guard categories", value(row, "llama_guard_categories")),
        ]
        story.append(table([["Result detail", "Value"]] + fields, [width*.43, width*.57]))
        for field, label in (
            ("objective", "Attack objective"), ("what_it_does", "Attack description"),
            ("attack_carrier", "Attack carrier"), ("obfuscation", "Obfuscation"),
            ("framing", "Framing"), ("stage", "Stage"),
            ("reason", "Evaluation reasoning"), ("error", "Error"),
            ("judge_reasoning", "AI Judge reasoning"),
            ("prompt_text", "Full user prompt"), ("response_text", "Full model response"),
            ("prompt_guard_raw_json", "Prompt Guard result"),
            ("llama_guard_raw_json", "Llama Guard result"),
            ("judge_raw_json", "Raw judge result"),
            ("raw_response_json", "Raw provider result"),
        ):
            text = value(row, field, "")
            if text or field in ("prompt_text", "response_text"):
                text_section(label, text or "(No response stored)")

    def decorate(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(BLUE)
        canvas.setLineWidth(2)
        canvas.line(18*mm, A4[1]-13*mm, A4[0]-18*mm, A4[1]-13*mm)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(18*mm, A4[1]-18*mm, "AI SECURITY LAB")
        canvas.setFont("Helvetica", 8)
        canvas.drawString(18*mm, 11*mm, f"BENCHMARK #{value(run, 'id')}  /  {generated}")
        canvas.drawRightString(A4[0]-18*mm, 11*mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return buffer.getvalue()
